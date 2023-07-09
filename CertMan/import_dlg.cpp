#include <QFileDialog>

#include "import_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_x509.h"
#include "commons.h"
#include "js_pki_eddsa.h"

static QStringList sDataTypeList = {
    "PrivateKey", "Encrypted PrivateKey", "Request(CSR)", "Certificate", "CRL", "PFX"
};

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

    if( strPath.isEmpty() )
    {
        manApplet->warningBox( tr( "select file to import"), this );
        return;
    }

    int nSelType = mDataTypeCombo->currentIndex();

    if( nSelType == 1 || nSelType == 5 )
    {
        if( strPass.length() < 1 )
        {
            manApplet->warningBox( tr("insert password"), this );
            mPasswordText->setFocus();
            return;
        }
    }

    BIN binSrc = {0,0};
    JS_BIN_fileReadBER( strPath.toLocal8Bit().toStdString().c_str(), &binSrc );

    if( nSelType == 0 || nSelType == 1 )
    {
        if( nSelType == 1 )
        {
            BIN binInfo = {0,0};
            BIN binPri = {0,0};

            ret = JS_PKI_decryptRSAPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );

            if( ret != 0 )
                ret = JS_PKI_decryptECPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );

            if( ret != 0 )
                ret = JS_PKI_decryptDSAPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );

            if( ret != 0 )
                ret = JS_PKI_decryptPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );

            if( ret == 0 )
            {
                ret = ImportKeyPair( &binPri );
            }

            JS_BIN_reset( &binInfo );
            JS_BIN_reset( &binPri );
        }
        else
            ret = ImportKeyPair( &binSrc );

        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightKeyPairList();
        }
    }
    else if( nSelType == 2 )
    {
        if( mImportKMSCheck->isChecked() )
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
    else if( nSelType == 3 )
    {
        ret = ImportCert( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightCertList( -2 );
        }
    }
    else if( nSelType == 4 )
    {
        if( mImportKMSCheck->isChecked() )
        {
            manApplet->warningBox( tr( "KMS can not import CRL" ), this );
            return;
        }

        ret = ImportCRL( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightCRLList(-2);
        }
    }
    else if( nSelType == 5 )
    {
        ret = ImportPFX( &binSrc );
        if( ret == 0 )
        {
            manApplet->mainWindow()->createRightCertList(-2);
        }
    }

    JS_BIN_reset( &binSrc );
    QDialog::accept();
}

void ImportDlg::initUI()
{
    mDataTypeCombo->addItems(sDataTypeList);

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT( clickFind()));
    connect( mDataTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
}

void ImportDlg::initialize()
{
    if( manApplet->isPRO() == false )
        mImportKMSCheck->hide();
}


void ImportDlg::clickFind()
{   
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter = "";

    if( mDataTypeCombo->currentIndex() == 0 )
        strFilter = "BER Files (*.ber *.der)";
    else if( mDataTypeCombo->currentIndex() == 1 )
        strFilter = "Private Key Files (*.key *.der)";
    else if( mDataTypeCombo->currentIndex() == 2 )
        strFilter = "CSF Files (*.csr *.der)";
    else if( mDataTypeCombo->currentIndex() == 3 )
        strFilter = "Cert Files (*.crt *.der)";
    else if( mDataTypeCombo->currentIndex() == 4 )
        strFilter = "CRL Files (*.crl *.der)";
    else if( mDataTypeCombo->currentIndex() == 5 )
        strFilter = "PFX Files (*.pfx *.der);;P12 Files (*.p12 *.der)";

    strFilter += ";;All Files (*.*)";

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Import files"),
                                                     QDir::currentPath(),
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}

void ImportDlg::dataTypeChanged( int index )
{
    if( index == 1 || index == 5 )
        mPasswordText->setEnabled(true);
    else {
        mPasswordText->setEnabled(false);
    }
}

int ImportDlg::ImportKeyPair( const BIN *pPriKey )
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

    if( pPriKey == NULL || pPriKey->nLen <= 0 ) return -1;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));
    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sDSAKey, 0x00, sizeof(sDSAKey));
    memset( &sRawKey, 0x00, sizeof(sRawKey));

    nKeyType = JS_PKI_getPriKeyType( pPriKey );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JS_PKI_getRSAKeyVal( pPriKey, &sRSAKey );
        strAlg = kMechRSA;
        nParam = ( strlen( sRSAKey.pD ) / 2 ) * 8;
        JS_PKI_encodeRSAPublicKey( &sRSAKey, &binPub );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        strAlg = kMechEC;
        JS_PKI_getECKeyVal( pPriKey, &sECKey );
        nParam = JS_PKI_getKeyParam( JS_PKI_KEY_TYPE_ECC, pPriKey );
        JS_PKI_encodeECPublicKey( &sECKey, &binPub );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        strAlg = kMechDSA;
        JS_PKI_getDSAKeyVal( pPriKey, &sDSAKey );
        nParam = ( strlen( sDSAKey.pG ) / 2 ) * 8;
        JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ED25519 || nKeyType == JS_PKI_KEY_TYPE_ED448 )
    {
        strAlg = kMechEdDSA;
        nParam = nKeyType;
        JS_PKI_getRawKeyVal( nKeyType, pPriKey, &sRawKey );
        JS_PKI_encodeRawPublicKey( &sRawKey, &binPub );
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

    if( mImportKMSCheck->isChecked() )
    {
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
        if( ret != 0 ) goto kmip_end;

        ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
        if( ret != 0 ) goto kmip_end;

        ret = JS_KMS_decodeRegisterRsp( &binRsp, &pUUID );
        if( ret != 0 ) goto kmip_end;

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

        ret = JS_KMS_encodeRegisterReq( pAuth, nKeyType, nParam, nType, &binPub, &binReq );
        if( ret != 0 ) goto kmip_end;

        ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
        if( ret != 0 ) goto kmip_end;

        ret = JS_KMS_decodeRegisterRsp( &binRsp, &pUUID );
        if( ret != 0 ) goto kmip_end;

    kmip_end :
        if( pSSL ) JS_SSL_clear( pSSL );
        if( pCTX ) JS_SSL_finish( &pCTX );
        if( pAuth ) JS_KMS_resetAuthentication( pAuth );
        if( pUUID ) JS_free( pUUID );

        JS_BIN_reset( &binReq );
        JS_BIN_reset( &binRsp );
        if( ret != 0 ) goto end;
    }

    keyPair.setAlg( strAlg );
    keyPair.setRegTime( time(NULL) );
    keyPair.setName( mNameText->text() );
    keyPair.setPublicKey( getHexString( &binPub) );
    keyPair.setParam( QString("Imported %1").arg(nParam) );

    ret = dbMgr->addKeyPairRec( keyPair );

 end :
    JS_PKI_resetRSAKeyVal( &sRSAKey );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetDSAKeyVal( &sDSAKey );
    JS_PKI_resetRawKeyVal( &sRawKey );
    JS_BIN_reset( &binPub );

    return ret;
}

void ImportDlg::setKMIPCheck()
{
    mImportKMSCheck->setChecked(true);
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

    if( mImportKMSCheck->isChecked() )
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

    ret = JS_PKI_getReqInfo( pCSR, &sReqInfo, &pExtInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCSR, &pHexCSR );

    req.setCSR( pHexCSR );
    req.setDN( sReqInfo.pSubjectDN );
    req.setHash( sReqInfo.pSignAlgorithm );
    req.setName( mNameText->text() );

    dbMgr->addReqRec( req );
    if( pHexCSR ) JS_free( pHexCSR );
    JS_PKI_resetReqInfo( &sReqInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

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
//    const char *pPasswd = "26c521a0c94b61580c780a46436f065ce658b73c";

    ret = JS_PKI_decodePFX( pPFX, strPasswd.toStdString().c_str(), &binPri, &binCert );
    if( ret != 0 ) return ret;

    ret = ImportCert( &binCert );
    if( ret != 0 ) return ret;

    ret = ImportKeyPair( &binPri );
    if( ret != 0 ) return ret;

    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPri );

    return 0;
}
