#include <QFileDialog>

#include "import_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_tools.h"
#include "js_pki_x509.h"
#include "commons.h"
#include "js_pki_eddsa.h"
#include "js_define.h"

static QStringList sDataTypeList = {
    "PrivateKey", "Encrypted PrivateKey", "Request(CSR)", "Certificate", "CRL", "PFX"
};

static QStringList sValueType = { "Hex", "Base64" };

ImportDlg::ImportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    initialize();
}

ImportDlg::~ImportDlg()
{

}

void ImportDlg::setType(int index)
{
    mDataTypeCombo->setCurrentIndex(index);
}

void ImportDlg::accept()
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    QString strPath = mPathText->text();
    QString strPass = mPasswordText->text();
    QString strValue = mValueText->toPlainText();

    int nSelType = mDataTypeCombo->currentIndex();

    if( nSelType == IMPORT_TYPE_ENC_PRIKEY || nSelType == IMPORT_TYPE_PFX )
    {
        if( strPass.length() < 1 )
        {
            manApplet->warningBox( tr("insert password"), this );
            mPasswordText->setFocus();
            return;
        }
    }

    BIN binSrc = {0,0};

    if( mUseFileCheck->isChecked() == true )
    {
        if( strPath.isEmpty() )
        {
            manApplet->warningBox( tr( "select file to import"), this );
            return;
        }

        ret = JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binSrc );
        if( ret <= 0 )
        {
            manApplet->warningBox( tr( "fail to read : %1").arg( strPass ), this );
            return;
        }
    }
    else
    {
        if( strValue.length() < 1 )
        {
            manApplet->warningBox( tr( "You have to insert value"), this );
            mValueText->setFocus();
            return;
        }

        getBINFromString( &binSrc, mValueTypeCombo->currentText(), strValue );
    }

    if( nSelType == IMPORT_TYPE_PRIKEY || nSelType == IMPORT_TYPE_ENC_PRIKEY )
    {
        if( nSelType == 1 )
        {
            BIN binInfo = {0,0};
            BIN binPri = {0,0};

            if( binSrc.nLen > 0 )
                ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );

            if( ret == 0 )
            {
                ret = ImportKeyPair( &binPri, JS_REC_STATUS_NOT_USED );
            }
            else
            {
                JS_BIN_reset( &binSrc );
                QString strMsg = tr("fail to decrypt private key: %1").arg( ret );
                manApplet->warningBox( strMsg, this );
                manApplet->elog( strMsg );
                QDialog::reject();
                return;
            }

            JS_BIN_reset( &binInfo );
            JS_BIN_reset( &binPri );
        }
        else
            ret = ImportKeyPair( &binSrc, JS_REC_STATUS_NOT_USED );

        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightKeyPairList();
        }
    }
    else if( nSelType == IMPORT_TYPE_CSR )
    {
        if( mToKMSCheck->isChecked() )
        {
            manApplet->warningBox( tr( "KMS can not import CSR" ), this );
            return;
        }

        ret = ImportRequest( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightRequestList();
        }
    }
    else if( nSelType == IMPORT_TYPE_CERT )
    {
        ret = ImportCert( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightCertList( -2 );
        }
    }
    else if( nSelType == IMPORT_TYPE_CRL )
    {
        if( mToKMSCheck->isChecked() )
        {
            manApplet->warningBox( tr( "KMS can not import CRL" ), this );
            JS_BIN_reset( &binSrc );
            return;
        }

        ret = ImportCRL( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightCRLList(-2);
        }
    }
    else if( nSelType == IMPORT_TYPE_PFX )
    {
        ret = ImportPFX( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightCertList(-2);
        }
    }

    if( ret != 0 )
    {
        JS_BIN_reset( &binSrc );
        QString strMsg = tr( "fail to import: %1").arg( ret );
        manApplet->warningBox( strMsg, this );
        manApplet->elog( strMsg );
        QDialog::reject();
        return;
    }

    manApplet->messageBox( tr( "Import is successful"), this );
    manApplet->setCurFile( strPath );
    JS_BIN_reset( &binSrc );
    QDialog::accept();
}

void ImportDlg::initUI()
{
    mDataTypeCombo->addItems(sDataTypeList);
    dataTypeChanged(0);

    mValueTypeCombo->addItems(sValueType);

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT( clickFind()));
    connect( mDataTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
    connect( mUseFileCheck, SIGNAL(clicked()), this, SLOT(checkUseFile()));
    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValue()));
}

void ImportDlg::initialize()
{
    if( manApplet->isPRO() == false )
        mToKMSCheck->hide();

    if( manApplet->settingsMgr()->PKCS11Use() == false )
        mToPKCS11Check->hide();

    checkUseFile();
}


void ImportDlg::clickFind()
{   
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter = "";
    QString strPath = mPathText->text();

    if( strPath.length() < 1 )
        strPath = manApplet->curFolder();

    if( mDataTypeCombo->currentIndex() == 0 )
        strFilter = "BER Files (*.ber *.der *.pem)";
    else if( mDataTypeCombo->currentIndex() == 1 )
        strFilter = "Private Key Files (*.key *.der *.pem)";
    else if( mDataTypeCombo->currentIndex() == 2 )
        strFilter = "CSF Files (*.csr *.der *.pem)";
    else if( mDataTypeCombo->currentIndex() == 3 )
        strFilter = "Cert Files (*.crt *.der *.pem)";
    else if( mDataTypeCombo->currentIndex() == 4 )
        strFilter = "CRL Files (*.crl *.der *.pem)";
    else if( mDataTypeCombo->currentIndex() == 5 )
        strFilter = "PFX Files (*.pfx *.der *.pem);;P12 Files (*.p12 *.der *.pem)";

    strFilter += ";;All Files (*.*)";

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Import files"),
                                                     strPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}

void ImportDlg::dataTypeChanged( int index )
{
    QString strType = mDataTypeCombo->currentText();

    if( manApplet->settingsMgr()->PKCS11Use() == true )
    {
        if( strType == "PrivateKey" || strType == "Encrypted PrivateKey" )
            mToPKCS11Check->setEnabled(true);
        else
            mToPKCS11Check->setEnabled(false);
    }

    if( strType == "Encrypted PrivateKey" || strType == "PFX" )
        mPasswordText->setEnabled(true);
    else {
        mPasswordText->setEnabled(false);
    }

    if( strType == "Certificate" || strType == "CRL" )
    {
        mNameText->setEnabled(false);
    }
    else
    {
        mNameText->setEnabled(true);
    }
}

int ImportDlg::ImportKeyPair( const BIN *pPriKey, int nStatus )
{
    int ret = 0;

    int nParam = -1;
    BIN binPub = {0,0};
    QString strAlg;
    KeyPairRec keyPair;
    int nKeyType = -1;
    JRSAKeyVal  sRSAKey;
    JECKeyVal   sECKey;
    JDSAKeyVal  sDSAKey;
    JRawKeyVal sRawKey;
    QString strParam;
    BIN binID = {0,0};

    if( pPriKey == NULL || pPriKey->nLen <= 0 ) return -1;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));
    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sDSAKey, 0x00, sizeof(sDSAKey));
    memset( &sRawKey, 0x00, sizeof(sRawKey));

    nKeyType = JS_PKI_getPriKeyType( pPriKey );

    if( manApplet->isLicense() == false )
    {
        if( nKeyType != JS_PKI_KEY_TYPE_RSA )
        {
            manApplet->elog( QString("Unlicense version support only RSA private key: %1").arg( nKeyType ));
            ret = -1;
            goto end;
        }
    }

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JS_PKI_getRSAKeyVal( pPriKey, &sRSAKey );
        strAlg = kMechRSA;
        nParam = ( strlen( sRSAKey.pD ) / 2 ) * 8;
        JS_PKI_encodeRSAPublicKey( &sRSAKey, &binPub );
        strParam = QString("%1").arg(nParam);
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC || nKeyType == JS_PKI_KEY_TYPE_SM2 )
    {
        strAlg = kMechEC;
        JS_PKI_getECKeyVal( pPriKey, &sECKey );
        nParam = JS_PKI_getKeyParam( JS_PKI_KEY_TYPE_ECC, pPriKey );
        JS_PKI_encodeECPublicKey( &sECKey, &binPub );

        strParam = JS_PKI_getSNFromNid( nParam );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        strAlg = kMechDSA;
        JS_PKI_getDSAKeyVal( pPriKey, &sDSAKey );
        nParam = ( strlen( sDSAKey.pG ) / 2 ) * 8;
        JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );
        strParam = QString("%1").arg(nParam);
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ED25519 || nKeyType == JS_PKI_KEY_TYPE_ED448 )
    {
        strAlg = kMechEdDSA;
        if( nKeyType == JS_PKI_KEY_TYPE_ED25519 )
            strParam = kMechEd25519;
        else
            strParam = kMechEd448;

        JS_PKI_getRawKeyVal( nKeyType, pPriKey, &sRawKey );
        JS_PKI_getRawPublicKeyFromPri( nKeyType, pPriKey, &binPub );
    }
    else
    {
        manApplet->elog( QString( "Invalid KeyType: %1").arg( nKeyType));
        ret = -1;
        goto end;
    }

    if( ret != 0  ) return -1;

    if( manApplet->isPasswd() )
    {
        QString strHex = manApplet->getEncPriHex( pPriKey );
        keyPair.setPrivateKey( strHex );
    }
    else
    {
        keyPair.setPrivateKey( getHexString( pPriKey ) );
    }

    if( manApplet->settingsMgr()->KMIPUse() && mToKMSCheck->isChecked() )
    {
        ret = ImportPriKeyToKMIP( nKeyType, pPriKey, nParam, &binPub, &binID );
        if( ret == 0 ) keyPair.setPrivateKey( getHexString( &binID ));
    }

    if( manApplet->settingsMgr()->PKCS11Use() && mToPKCS11Check->isChecked() )
    {
        ret = ImportPriKeyToPKCS11( nKeyType, pPriKey, &binPub, &binID );
        if( ret == 0 ) keyPair.setPrivateKey( getHexString( &binID ));
    }

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to import PrivateKey: %1").arg(ret));
        ret = -1;
        goto end;
    }

    keyPair.setAlg( strAlg );
    keyPair.setRegTime( time(NULL) );
    keyPair.setName( mNameText->text() );
    keyPair.setPublicKey( getHexString( &binPub) );
    keyPair.setParam( strParam );
    keyPair.setStatus( nStatus );

    ret = dbMgr->addKeyPairRec( keyPair );

 end :
    if( ret == 0 ) manApplet->log( "The key pair is imported successfully" );
    JS_PKI_resetRSAKeyVal( &sRSAKey );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetDSAKeyVal( &sDSAKey );
    JS_PKI_resetRawKeyVal( &sRawKey );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binID );

    return ret;
}

int ImportDlg::ImportPriKeyToKMIP( int nKeyType, const BIN *pPriKey, int nParam, const BIN *pPubInfoKey, BIN *pID )
{
    int ret = 0;
    SSL_CTX     *pCTX = NULL;
    SSL         *pSSL = NULL;
    Authentication  *pAuth = NULL;
    BIN         binReq = {0,0};
    BIN         binRsp = {0,0};

    int nType = JS_KMS_OBJECT_TYPE_PRIKEY;

    char *pUUID = NULL;

    if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        if( nParam != NID_X9_62_prime256v1 )
        {
            goto end;
        }

        nParam = KMIP_CURVE_P_256;
    }

    ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_KMS_encodeRegisterReq( pAuth, nKeyType, nParam, nType, pPriKey, &binReq );
    if( ret != 0 ) goto end;

    ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    if( ret != 0 ) goto end;

    ret = JS_KMS_decodeRegisterRsp( &binRsp, &pUUID );
    if( ret != 0 ) goto end;

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth ) JS_KMS_resetAuthentication( pAuth );

    pSSL = NULL;
    pCTX = NULL;
    pAuth = NULL;

    nType = JS_KMS_OBJECT_TYPE_PUBKEY;

    ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_KMS_encodeRegisterReq( pAuth, nKeyType, nParam, nType, pPubInfoKey, &binReq );
    if( ret != 0 ) goto end;

    ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    if( ret != 0 ) goto end;

    ret = JS_KMS_decodeRegisterRsp( &binRsp, &pUUID );
    if( ret != 0 ) goto end;

    JS_BIN_set( pID, (unsigned char *)pUUID, strlen(pUUID));

end :
    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth ) JS_KMS_resetAuthentication( pAuth );
    if( pUUID ) JS_free( pUUID );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    return ret;
}

int ImportDlg::ImportPriKeyToPKCS11( int nKeyType, const BIN *pPriKey, const BIN *pPubInfoKey, BIN *pID )
{
    int ret = 0;
    BIN binHash = {0,0};
    JP11_CTX *pCTX = NULL;

    JRSAKeyVal sRSAKey;
    JECKeyVal sECKey;
    JDSAKeyVal sDSAKey;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));
    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    int nIndex = manApplet->settingsMgr()->slotIndex();
    QString strPIN = manApplet->settingsMgr()->PKCS11Pin();
    QString strName = mNameText->text();

    pCTX = (JP11_CTX *)manApplet->P11CTX();

    CK_SESSION_HANDLE hSession = getP11Session( pCTX, nIndex, strPIN );

    if( hSession < 0 )
    {
        manApplet->elog( "fail to get P11Session" );
        goto end;
    }

    JS_PKI_genHash( "SHA1", pPubInfoKey, &binHash );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JS_PKI_getRSAKeyVal( pPriKey, &sRSAKey );
        ret = createRSAPrivateKeyP11( pCTX, strName, &binHash, &sRSAKey );
        if( ret != 0 ) goto end;
        ret = createRSAPublicKeyP11( pCTX, strName, &binHash, &sRSAKey );
        if( ret != 0 ) goto end;
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        JS_PKI_getECKeyVal( pPriKey, &sECKey );
        ret = createECPrivateKeyP11( pCTX, strName, &binHash, &sECKey );
        if( ret != 0 ) goto end;
        ret = createECPublicKeyP11( pCTX, strName, &binHash, &sECKey );
        if( ret != 0 ) goto end;
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        JS_PKI_getDSAKeyVal( pPriKey, &sDSAKey );
        ret = createDSAPrivateKeyP11( pCTX, strName, &binHash, &sDSAKey );
        if( ret != 0 ) goto end;
        ret = createDSAPublicKeyP11( pCTX, strName, &binHash, &sDSAKey );
        if( ret != 0 ) goto end;
    }
    else
    {
        ret = -1;
        goto end;
    }


    JS_BIN_copy( pID, &binHash );
    ret = 0;

end :
    JS_PKCS11_Logout( pCTX );
    JS_PKCS11_CloseSession( pCTX );

    JS_BIN_reset( &binHash );
    JS_PKI_resetRSAKeyVal( &sRSAKey );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetDSAKeyVal( &sDSAKey );

    return ret;
}

void ImportDlg::setKMIPCheck()
{
    mToKMSCheck->setChecked(true);
}

void ImportDlg::checkUseFile()
{
    bool bVal = mUseFileCheck->isChecked();

    mValueGroup->setEnabled( !bVal );
    mPathText->setEnabled( bVal );
    mFindBtn->setEnabled( bVal );
}

void ImportDlg::changeValue()
{
    QString strVal = mValueText->toPlainText();

    int nLen = getDataLen( mValueTypeCombo->currentText(), strVal );
    mValueLenText->setText( QString("%1").arg(nLen));
}

int ImportDlg::ImportCert( const BIN *pCert )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    char *pHexCert = NULL;
    JCertInfo sCertInfo;

    JExtensionInfoList *pExtInfoList = NULL;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( pCert, &sCertInfo, &pExtInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCert, &pHexCert );

    if( mToKMSCheck->isChecked() )
    {
        SSL_CTX     *pCTX = NULL;
        SSL         *pSSL = NULL;
        Authentication  *pAuth = NULL;
        BIN         binReq = {0,0};
        BIN         binRsp = {0,0};

        int nAlg = -1;
        int nParam = -1;
        int nType = JS_KMS_OBJECT_TYPE_CERT;

        char *pUUID = NULL;

        ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
        if( ret != 0 )
        {
            goto end;
        }

        JS_KMS_encodeRegisterReq( pAuth, nAlg, nParam, nType, pCert, &binReq );
        JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
        JS_KMS_decodeRegisterRsp( &binRsp, &pUUID );

        if( pSSL ) JS_SSL_clear( pSSL );
        if( pCTX ) JS_SSL_finish( &pCTX );
        if( pAuth ) JS_KMS_resetAuthentication( pAuth );
        if( pUUID ) JS_free( pUUID );

        JS_BIN_reset( &binReq );
        JS_BIN_reset( &binRsp );
    }
    else
    {
        CertRec     cert;
        cert.setCert( pHexCert );
        cert.setRegTime( time(NULL) );
        cert.setSubjectDN( sCertInfo.pSubjectName );
        cert.setIssuerNum( -2 );
        cert.setSignAlg( sCertInfo.pSignAlgorithm );

        dbMgr->addCertRec( cert );
    }

end :
    if( ret == 0 ) manApplet->log( "The request is imported successfully" );

    if( pHexCert ) JS_free( pHexCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return ret;
}

int ImportDlg::ImportCRL( const BIN *pCRL )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    JCRLInfo sCRLInfo;
    char *pHexCRL = NULL;
    CRLRec crl;
    JExtensionInfoList *pExtInfoList = NULL;
    JRevokeInfoList *pRevokeInfoList = NULL;

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    ret = JS_PKI_getCRLInfo( pCRL, &sCRLInfo, &pExtInfoList, &pRevokeInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCRL, &pHexCRL );

    crl.setCRL( pHexCRL );
    crl.setRegTime( time(NULL) );
    crl.setSignAlg( sCRLInfo.pSignAlgorithm );
    crl.setIssuerNum( -2 );

    dbMgr->addCRLRec( crl );

    if( pHexCRL ) JS_free( pHexCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pRevokeInfoList ) JS_PKI_resetRevokeInfoList( &pRevokeInfoList );

    manApplet->log( "The CRL is imported successfully" );

    return 0;
}

int ImportDlg::ImportRequest( const BIN *pCSR )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    ReqRec  req;
    JReqInfo   sReqInfo;
    char *pHexCSR = NULL;
    JExtensionInfoList *pExtInfoList = NULL;
    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    ret = JS_PKI_getReqInfo( pCSR, &sReqInfo, 1, &pExtInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCSR, &pHexCSR );

    req.setCSR( pHexCSR );
    req.setRegTime( time(NULL) );
    req.setDN( sReqInfo.pSubjectDN );
    req.setHash( sReqInfo.pSignAlgorithm );
    req.setName( mNameText->text() );
    req.setStatus( 0 );

    dbMgr->addReqRec( req );
    if( pHexCSR ) JS_free( pHexCSR );
    JS_PKI_resetReqInfo( &sReqInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    manApplet->log( "The request is imported successfully" );

    return 0;
}

int ImportDlg::ImportPFX( const BIN *pPFX )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    BIN binCert = {0,0};
    BIN binPri = {0,0};

    QString strPasswd = mPasswordText->text().toStdString().c_str();

    ret = JS_PKI_decodePFX( pPFX, strPasswd.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to decode pfx:%1").arg(ret));
        goto end;
    }

    ret = ImportCert( &binCert );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to import certificate:%1").arg( ret ));
        goto end;
    }

    ret = ImportKeyPair( &binPri, JS_REC_STATUS_USED );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to import key pair:%1").arg( ret ));
        goto end;
    }

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPri );

    return ret;
}
