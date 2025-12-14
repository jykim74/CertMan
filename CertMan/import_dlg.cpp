/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>

#include "import_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_key.h"
#include "js_pki_tools.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "commons.h"
#include "js_pki_raw.h"
#include "js_define.h"
#include "crl_info_dlg.h"
#include "js_pqc.h"
#include "man_tree_view.h"

static QStringList sDataTypeList = {
    "PrivateKey", "Encrypted PrivateKey", "Request(CSR)", "Certificate", "CRL", "PFX"
};

ImportDlg::ImportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setAcceptDrops( true );

    initUI();
    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ImportDlg::~ImportDlg()
{

}

void ImportDlg::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls() || event->mimeData()->hasText()) {
        event->acceptProposedAction();  // 드랍 허용
    }
}

void ImportDlg::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QList<QUrl> urls = event->mimeData()->urls();

        for (const QUrl &url : urls)
        {
            manApplet->log( QString( "url: %1").arg( url.toLocalFile() ));

            if( mUseFileCheck->isChecked() == true )
            {
                mPathText->setText( url.toLocalFile() );
            }
            else
            {
                BIN binData = {0,0};
                QString strValue;

                JS_BIN_fileReadBER( url.toLocalFile().toLocal8Bit().toStdString().c_str(), &binData );
                strValue = getStringFromBIN( &binData, mValueTypeCombo->currentText() );
                mValueText->setPlainText( strValue );
                JS_BIN_reset( &binData );
            }

            break;
        }
    } else if (event->mimeData()->hasText()) {

    }
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
            manApplet->warningBox( tr("Please enter a password"), this );
            mPasswordText->setFocus();
            return;
        }
    }

    BIN binSrc = {0,0};

    if( mUseFileCheck->isChecked() == true )
    {
        if( strPath.isEmpty() )
        {
            manApplet->warningBox( tr( "Select the file to import"), this );
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
            manApplet->warningBox( tr( "Please enter a value"), this );
            mValueText->setFocus();
            return;
        }

        ret = getBINFromString( &binSrc, mValueTypeCombo->currentText(), strValue );
        if( ret < 0 )
        {
            manApplet->formatWarn( ret, this );
            return;
        }
    }

    if( nSelType == IMPORT_TYPE_PRIKEY || nSelType == IMPORT_TYPE_ENC_PRIKEY )
    {
        if( nSelType == IMPORT_TYPE_ENC_PRIKEY )
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
                QString strMsg = tr("Private key decryption failed [%1]").arg( ret );
                manApplet->warnLog( strMsg, this );
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
//            manApplet->mainWindow()->createRightKeyPairList();
            manApplet->clickTreeMenu( CM_ITEM_TYPE_KEYPAIR );
        }
    }
    else if( nSelType == IMPORT_TYPE_CSR )
    {
        if( mToKMSCheck->isChecked() )
        {
            manApplet->warningBox( tr( "Key management server does not support importing CSR" ), this );
            return;
        }

        ret = ImportRequest( &binSrc );
        if( ret == 0 )
        {
//            manApplet->mainWindow()->createRightRequestList();
            manApplet->clickTreeMenu( CM_ITEM_TYPE_REQUEST );
        }
    }
    else if( nSelType == IMPORT_TYPE_CERT )
    {
        ret = ImportCert( &binSrc );
        if( ret == 0 )
        {
//            manApplet->mainWindow()->createRightCertList( kImportNum );
            manApplet->clickTreeMenu( CM_ITEM_TYPE_IMPORT_CERT );
        }
    }
    else if( nSelType == IMPORT_TYPE_CRL )
    {
        if( mToKMSCheck->isChecked() )
        {
            manApplet->warningBox( tr( "Key management server does not support importing CRL" ), this );
            JS_BIN_reset( &binSrc );
            return;
        }

        ret = ImportCRL( &binSrc );
        if( ret == 0 )
        {
//            manApplet->mainWindow()->createRightCRLList( kImportNum );
            manApplet->clickTreeMenu( CM_ITEM_TYPE_IMPORT_CRL );
        }
    }
    else if( nSelType == IMPORT_TYPE_PFX )
    {
        ret = ImportPFX( &binSrc );
        if( ret == 0 )
        {
//            manApplet->mainWindow()->createRightCertList( kImportNum );
            manApplet->clickTreeMenu( CM_ITEM_TYPE_IMPORT_CERT );
        }
    }

    if( ret != 0 )
    {
        JS_BIN_reset( &binSrc );
        QString strMsg = tr( "import failed: %1").arg( JERR(ret) );
        manApplet->warningBox( strMsg, this );
        manApplet->elog( strMsg );
        QDialog::reject();
        return;
    }

    manApplet->messageBox( tr( "Import was successful"), this );
    JS_BIN_reset( &binSrc );
    QDialog::accept();
}

void ImportDlg::initUI()
{
    mDataTypeCombo->addItems(sDataTypeList);
    dataTypeChanged(0);

    mValueTypeCombo->addItems( kDataBinTypeList );

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT( clickFind()));
    connect( mDataTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
    connect( mUseFileCheck, SIGNAL(clicked()), this, SLOT(checkUseFile()));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValue()));
    connect( mValueText, SIGNAL(textChanged()), this, SLOT(changeValue()));

    mPathText->setPlaceholderText( tr( "Find a data file" ));
    mUseFileCheck->setChecked(true);
}

void ImportDlg::initialize()
{
    if( manApplet->isPRO() == false )
        mToKMSCheck->hide();

    if( manApplet->P11CTX() == NULL )
        mToPKCS11Check->setDisabled(true);

    checkUseFile();
}


void ImportDlg::clickFind()
{   
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strPath = mPathText->text();
    int nFileType = JS_FILE_TYPE_ALL;

    if( strPath.length() < 1 )
        strPath = manApplet->curPath();

    if( mDataTypeCombo->currentIndex() == 0 )
        nFileType = JS_FILE_TYPE_BER;
    else if( mDataTypeCombo->currentIndex() == 1 )
        nFileType = JS_FILE_TYPE_PRIKEY;
    else if( mDataTypeCombo->currentIndex() == 2 )
        nFileType = JS_FILE_TYPE_CSR;
    else if( mDataTypeCombo->currentIndex() == 3 )
        nFileType = JS_FILE_TYPE_CERT;
    else if( mDataTypeCombo->currentIndex() == 4 )
        nFileType = JS_FILE_TYPE_CRL;
    else if( mDataTypeCombo->currentIndex() == 5 )
        nFileType = JS_FILE_TYPE_PFX;

    QString fileName = manApplet->findFile( this, nFileType, strPath );
    if( fileName.length() > 0 ) mPathText->setText( fileName );
}

void ImportDlg::dataTypeChanged( int index )
{
    QString strType = mDataTypeCombo->currentText();
    mHeadLabel->setText( tr("Import %1" ).arg( strType ));

    if( manApplet->settingsMgr()->PKCS11Use() == true )
    {
        if( strType == "PrivateKey" || strType == "Encrypted PrivateKey" )
            mToPKCS11Check->setEnabled(true);
        else
            mToPKCS11Check->setEnabled(false);
    }

    if( strType == "Encrypted PrivateKey" || strType == "PFX" )
    {
        mPasswordLabel->setEnabled( true );
        mPasswordText->setEnabled(true);
    }
    else {
        mPasswordLabel->setEnabled( false );
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

    JS_PKI_getPriKeyAlgParam( pPriKey, &nKeyType, &nParam );

    if( manApplet->isLicense() == false )
    {
        if( nKeyType != JS_PKI_KEY_TYPE_RSA )
        {
            manApplet->warnLog( tr("Unlicense version support only RSA algorithm: %1").arg( nKeyType ), this );
            ret = -1;
            goto end;
        }
    }

    strAlg = JS_PKI_getKeyAlgName( nKeyType );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JS_PKI_getRSAKeyVal( pPriKey, &sRSAKey );
        JS_PKI_encodeRSAPublicKey( &sRSAKey, &binPub );
        strParam = QString("%1").arg(nParam);
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA || nKeyType == JS_PKI_KEY_TYPE_SM2 )
    {
        JS_PKI_getECKeyVal( pPriKey, &sECKey );
        JS_PKI_encodeECPublicKey( &sECKey, &binPub );
        strParam = JS_PKI_getSNFromNid( nParam );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        JS_PKI_getDSAKeyVal( pPriKey, &sDSAKey );
        JS_PKI_encodeDSAPublicKey( &sDSAKey, &binPub );
        strParam = QString("%1").arg(nParam);
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_EDDSA )
    {   
        strParam = JS_EDDSA_getParamName( nParam );

        JS_PKI_getRawKeyVal( pPriKey, &sRawKey );
        JS_PKI_getRawPublicKeyFromPri( pPriKey, &binPub );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ML_DSA || nKeyType == JS_PKI_KEY_TYPE_SLH_DSA )
    {
        strParam = JS_PQC_paramName( nParam );

        JS_PKI_getRawKeyVal( pPriKey, &sRawKey );
        JS_PKI_getRawPublicKeyFromPri( pPriKey, &binPub );
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
        manApplet->elog( QString( "failed to import PrivateKey: %1").arg(ret));
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
    if( ret == 0 ) manApplet->log( "Keypair import successful" );
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

    if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
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

    ret = JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
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

    ret = JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
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

    ret = getP11Session( pCTX, nIndex, strPIN );

    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to get P11Session: %1" ).arg( ret ) );
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
    else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
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

    mValueGroup->setEnabled( !bVal );
}

void ImportDlg::changeValue()
{
    QString strVal = mValueText->toPlainText();

    QString strLen = getDataLenString( mValueTypeCombo->currentText(), strVal );
    mValueLenText->setText( QString("%1").arg(strLen));
}

int ImportDlg::ImportCert( const BIN *pCert )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;
    int nSelf = 0;

    char *pHexCert = NULL;
    JCertInfo sCertInfo;

    JExtensionInfoList *pExtInfoList = NULL;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo2( pCert, &sCertInfo, &pExtInfoList, &nSelf );
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
        JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
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
        cert.setIssuerNum( kImportNum );
        cert.setSignAlg( sCertInfo.pSignAlgorithm );
        cert.setSelf( nSelf );

        dbMgr->addCertRec( cert );
    }

end :
    if( ret == 0 ) manApplet->log( "Certificate import successful" );

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
    QString strExt;
    QString strCRLDP;

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    ret = JS_PKI_getCRLInfo( pCRL, &sCRLInfo, &pExtInfoList, &pRevokeInfoList );
    if( ret != 0 ) return ret;

    strExt = CRLInfoDlg::getValueFromExtList( JS_PKI_ExtNameIDP, pExtInfoList );
    strCRLDP = CRLInfoDlg::getCRL_URIFromExt( strExt );

    JS_BIN_encodeHex( pCRL, &pHexCRL );

    crl.setCRL( pHexCRL );
    crl.setRegTime( time(NULL) );
    crl.setSignAlg( sCRLInfo.pSignAlgorithm );
    crl.setIssuerNum( kImportNum );
    crl.setThisUpdate( sCRLInfo.tThisUpdate );
    crl.setNextUpdate( sCRLInfo.tNextUpdate );
    if( strCRLDP.length() > 0 ) crl.setCRLDP( strCRLDP );

    dbMgr->addCRLRec( crl );

    if( pHexCRL ) JS_free( pHexCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pRevokeInfoList ) JS_PKI_resetRevokeInfoList( &pRevokeInfoList );

    manApplet->log( "CRL import successful" );

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

    manApplet->log( "CSR import successful" );

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
        manApplet->elog( QString( "failed to decode pfx:%1").arg(ret));
        goto end;
    }

    ret = ImportCert( &binCert );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to import certificate:%1").arg( ret ));
        goto end;
    }

    ret = ImportKeyPair( &binPri, JS_REC_STATUS_USED );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to import key pair:%1").arg( ret ));
        goto end;
    }

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPri );

    return ret;
}
