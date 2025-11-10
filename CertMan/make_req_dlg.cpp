/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "make_req_dlg.h"
#include "ui_make_req_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "key_pair_rec.h"
#include "req_rec.h"
#include "db_mgr.h"
#include "js_gen.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_raw.h"
#include "js_pki_ext.h"
#include "js_define.h"
#include "settings_mgr.h"
#include "commons.h"
#include "pin_dlg.h"
#include "make_dn_dlg.h"
#include "ca_man_dlg.h"
#include "profile_man_dlg.h"
#include "view_cert_profile_dlg.h"

const QString sUseExtension = "UseExtension";

static QStringList sMechList = {
    JS_PKI_KEY_NAME_RSA, JS_PKI_KEY_NAME_ECDSA, JS_PKI_KEY_NAME_DSA,
    JS_PKI_KEY_NAME_EDDSA, JS_PKI_KEY_NAME_ML_DSA, JS_PKI_KEY_NAME_SLH_DSA
};

MakeReqDlg::MakeReqDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mKeyNumText, SIGNAL(textChanged(QString)), this, SLOT(keyNumChanged()));
    connect( mProfileNumText, SIGNAL(textChanged(QString)), this, SLOT(profileNumChanged()));

    connect( mGenKeyPairCheck, SIGNAL(clicked()), this, SLOT(checkGenKeyPair()));
    connect( mNewOptionCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(newOptionChanged(int)));
    connect( mUseExtensionCheck, SIGNAL(clicked()), this, SLOT(checkExtension()));
    connect( mMakeDNBtn, SIGNAL(clicked()), this, SLOT(clickMakeDN()));

    connect( mRSARadio, SIGNAL(clicked()), this, SLOT(clickRSA()));
    connect( mECDSARadio, SIGNAL(clicked()), this, SLOT(clickECDSA()));
    connect( mDSARadio, SIGNAL(clicked()), this, SLOT(clickDSA()));
    connect( mEdDSARadio, SIGNAL(clicked()), this, SLOT(clickEdDSA()));
    connect( mSM2Radio, SIGNAL(clicked()), this, SLOT(clickSM2()));
    connect( mML_DSARadio, SIGNAL(clicked()), this, SLOT(clickML_DSA()));
    connect( mSLH_DSARadio, SIGNAL(clicked()), this, SLOT(clickSLH_DSA()));

    connect( mPKCS11Check, SIGNAL(clicked()), this, SLOT(checkPKCS11()));
    connect( mKMIPCheck, SIGNAL(clicked()), this, SLOT(checkKMIP()));

    connect( mSelectKeyPairBtn, SIGNAL(clicked()), this, SLOT(clickSelectKeyPair()));
    connect( mSelectProfileBtn, SIGNAL(clicked()), this, SLOT(clickSelectProfile()));
    connect( mViewProfileBtn, SIGNAL(clicked()), this, SLOT(clickViewProfile()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mSelTab->layout()->setSpacing(5);
    mSelTab->layout()->setMargin(5);
    mGenTab->layout()->setSpacing(5);
    mGenTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeReqDlg::~MakeReqDlg()
{

}

void MakeReqDlg::setKeyNum( int nKeyNum )
{
    mKeyNumText->setText( QString( "%1").arg( nKeyNum) );
}


const QString MakeReqDlg::getMechanism()
{
    QString strMech;

    if( mRSARadio->isChecked() )
    {
        if( mPKCS11Check->isChecked() )
            strMech = kMechPKCS11_RSA;
        else if( mKMIPCheck->isChecked() )
            strMech = kMechKMIP_RSA;
        else
            strMech = JS_PKI_KEY_NAME_RSA;
    }
    else if( mECDSARadio->isChecked() )
    {
        if( mPKCS11Check->isChecked() )
            strMech = kMechPKCS11_ECDSA;
        else if( mKMIPCheck->isChecked() )
            strMech = kMechKMIP_ECDSA;
        else
            strMech = JS_PKI_KEY_NAME_ECDSA;
    }
    else if( mDSARadio->isChecked() )
    {
        if( mPKCS11Check->isChecked() )
            strMech = kMechPKCS11_DSA;
        else
            strMech = JS_PKI_KEY_NAME_DSA;
    }
    else if( mEdDSARadio->isChecked() )
    {
        strMech = JS_PKI_KEY_NAME_EDDSA;
    }
    else if( mSM2Radio->isChecked() )
    {
        strMech = JS_PKI_KEY_NAME_SM2;
    }
    else if( mML_DSARadio->isChecked() )
    {
        strMech = JS_PKI_KEY_NAME_ML_DSA;
    }
    else if( mSLH_DSARadio->isChecked() )
    {
        strMech = JS_PKI_KEY_NAME_SLH_DSA;
    }

    return strMech;
}

void MakeReqDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( manApplet->isPRO() == false )
    {
        mKMIPCheck->hide();
    }

    if( manApplet->P11CTX() == NULL )
    {
        mPKCS11Check->setEnabled( false );
    }

    if( manApplet->isLicense() == false )
    {
        mRSARadio->setChecked(true);

        mECDSARadio->setEnabled(false);
        mDSARadio->setEnabled(false);
        mEdDSARadio->setEnabled(false);
        mSM2Radio->setEnabled(false);
        mML_DSARadio->setEnabled( false );
        mSLH_DSARadio->setEnabled( false );
    }

    mHashCombo->addItems(kHashList);
    mHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

    mNewExponentText->setText( "65537" );
    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kRSAOptionList );
    mNewOptionCombo->setCurrentText( "2048" );

    QString strKeyTypeParam = manApplet->settingsMgr()->keyTypeParam();
    if( strKeyTypeParam.length() > 1 )
    {
        QStringList typeParam = strKeyTypeParam.split(":");

        if( typeParam.size() > 0 )
        {
            QString strAlg = typeParam.at(0);

            if( strAlg == JS_PKI_KEY_NAME_RSA )
                mRSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_ECDSA )
                mECDSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_DSA )
                mDSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_SM2 )
                mSM2Radio->click();
            else if( strAlg == JS_PKI_KEY_NAME_EDDSA )
                mEdDSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
                mML_DSARadio->click();
            else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
                mSLH_DSARadio->click();
        }

        if( typeParam.size() > 1 )
        {
            QString strParam = typeParam.at(1);
            mNewOptionCombo->setCurrentText( strParam );
        }
    }
    else
    {
        mRSARadio->click();
    }
}

int MakeReqDlg::genKeyPair( KeyPairRec& keyPair )
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    char *pPriHex = NULL;
    char *pPubHex = NULL;
    int nSeq = 0;

    QString strAlg = getMechanism();
    QString strName = mNewKeyNameText->text();
    int nExponent = mNewExponentText->text().toInt();
    QString strParam = mNewOptionCombo->currentText();

    if( strName.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a key name" ), this );
        mNewKeyNameText->setFocus();
        return -1;
    }

    if( strAlg == JS_PKI_KEY_NAME_RSA )
    {
        int nKeySize = strParam.toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
    }
    else if( strAlg == JS_PKI_KEY_NAME_ECDSA )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strAlg == JS_PKI_KEY_NAME_SM2 )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strAlg == JS_PKI_KEY_NAME_DSA )
    {
        int nKeySize = strParam.toInt();

        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &binPub, &binPri );
    }
    else if( strAlg == JS_PKI_KEY_NAME_EDDSA )
    {
        int nParam = 0;

        if(  strParam == JS_EDDSA_PARAM_NAME_25519 )
            nParam = JS_EDDSA_PARAM_25519;
        else if( strParam == JS_EDDSA_PARAM_NAME_448 )
            nParam = JS_EDDSA_PARAM_448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
    }
    else if( strAlg == JS_PKI_KEY_NAME_ML_DSA )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_ML_DSA_genKeyPair( nParam, &binPub, &binPri );
    }
    else if( strAlg == JS_PKI_KEY_NAME_SLH_DSA )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_SLH_DSA_genKeyPair( nParam, &binPub, &binPri );
    }
    else if( isPKCS11Private( strAlg ) == true )
    {
        if( manApplet->settingsMgr()->PKCS11Use() == false )
        {
            manApplet->warningBox( tr("No PKCS11 settings"), this );
            ret = -1;
            goto end;
        }

        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nIndex = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        if( pP11CTX == NULL )
        {
            manApplet->elog( QString("PKCS11 library was not loaded") );
            ret = -1;
            goto end;
        }

        ret = getP11Session( pP11CTX, nIndex, strPIN );

        if( ret != 0 )
        {
            manApplet->elog( QString( "failed to get PKCS11 Session: %1" ).arg(ret) );
            goto end;
        }

        ret = genKeyPairWithP11(
                    (JP11_CTX *)manApplet->P11CTX(),
                    strName,
                    strAlg,
                    strParam,
                    nExponent,
                    &binPri,
                    &binPub );

        JS_PKCS11_Logout( (JP11_CTX *)manApplet->P11CTX() );
        JS_PKCS11_CloseSession( (JP11_CTX *)manApplet->P11CTX() );
    }
    else if( isKMIPPrivate( strAlg ) == true )
    {
        ret = genKeyPairWithKMIP(
                    manApplet->settingsMgr(),
                    strAlg,
                    strParam,
                    &binPri,
                    &binPub );
    }

    if( ret != 0 )
    {
        goto end;
    }

    if( isInternalPrivate( strAlg ) == true )
    {
        if( manApplet->isPasswd() )
        {
            QString strHex = manApplet->getEncPriHex( &binPri );
            keyPair.setPrivateKey( strHex );
        }
        else
        {
            JS_BIN_encodeHex( &binPri, &pPriHex );
            keyPair.setPrivateKey( pPriHex );
        }
    }
    else
    {
        JS_BIN_encodeHex( &binPri, &pPriHex );
        keyPair.setPrivateKey( pPriHex );
    }

    JS_BIN_encodeHex( &binPub, &pPubHex );
    nSeq = manApplet->dbMgr()->getNextVal( "TB_KEY_PAIR" );

    keyPair.setNum( nSeq );
    keyPair.setAlg( strAlg );
    keyPair.setRegTime( time(NULL) );
    keyPair.setName( strName );
    keyPair.setParam( strParam );
    keyPair.setPublicKey( pPubHex );
    keyPair.setStatus(0);


    ret = manApplet->dbMgr()->addKeyPairRec( keyPair );
    if( ret == 0 )
    {
        if( manApplet->isPRO() ) addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_KEY_PAIR, "" );
    }
    else
    {
        manApplet->warningBox( tr( "failed to generate key pair: %1").arg(JERR(ret)), this );
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    if( pPriHex ) JS_free( pPriHex );
    if( pPubHex ) JS_free( pPubHex );

    return ret;
}

void MakeReqDlg::accept()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binCSR = {0,0};
    BIN binPubKey = {0,0};
    BIN binKeyID = {0,0};
    char *pHexCSR = NULL;

    KeyPairRec keyRec;
    ReqRec reqRec;
    JExtensionInfoList *pExtInfoList = NULL;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();
    QString strChallenge = mChallengePassText->text();
    QString strUnstructuredName = mUnstructuredNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter a name"), this );
        mNameText->setFocus();
        return;
    }

    QString strDN = mDNText->text();

    if( strDN.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter a DN"), this );
        mDNText->setFocus();
        return;
    }

    QString strKeyNum;
    QString strProfileNum;

    if( mUseExtensionCheck->isChecked() )
    {
        if( mProfileNumText->text().length() < 1 )
        {
            if( mProfileNumText->text().length() < 1 )
            {
                manApplet->warningBox( tr( "Please select a profile"), this );
                return;
            }
        }

        strProfileNum = mProfileNumText->text();
    }

    QString strAlg;
    QString strHash = mHashCombo->currentText();
    QString strParam;

    if( mGenKeyPairCheck->isChecked() )
    {
        ret = genKeyPair( keyRec );
        if( ret != JSR_OK ) goto end;

        strParam = mNewOptionCombo->currentText();
        strAlg = getMechanism();
        QString strKeyParam = QString( "%1:%2" )
                                  .arg( getKeyMechType( strAlg.toStdString().c_str() ))
                                  .arg( strParam );

        manApplet->settingsMgr()->setKeyTypeParam( strKeyParam );
    }
    else
    {
        if( mKeyNumText->text().length() < 1 )
        {
            clickSelectKeyPair();

            if( mKeyNumText->text().length() < 1 )
            {
                manApplet->warningBox( tr( "Please select a keypair"), this );
                return;
            }
        }

        strKeyNum = mKeyNumText->text();

        int keyIdx = strKeyNum.toInt();
        manApplet->dbMgr()->getKeyPairRec( keyIdx, keyRec );
        strAlg = mAlgorithmText->text();
        strParam = mOptionText->text();
    }

    JS_BIN_decodeHex( keyRec.getPublicKey().toStdString().c_str(), &binPubKey );
    JS_PKI_getPublicKeyValue( &binPubKey, &binKeyID );

    if( mUseExtensionCheck->isChecked() )
    {
        int profileIdx = strProfileNum.toInt();
        CertProfileRec profileRec;
        QList<ProfileExtRec> profileExtList;

        ret = manApplet->dbMgr()->getCertProfileRec( profileIdx, profileRec );

        dbMgr->getCertProfileExtensionList( profileRec.getNum(), profileExtList );
        for( int i=0; i < profileExtList.size(); i++ )
        {
            JExtensionInfo sExtInfo;
            ProfileExtRec profileExt = profileExtList.at(i);

            memset( &sExtInfo, 0x00, sizeof(sExtInfo));

            if( profileExt.getSN() == JS_PKI_ExtNameSKI )
            {
                profileExt.setValue( getHexString( &binKeyID ) );
            }
            else if( profileExt.getSN() == JS_PKI_ExtNameAKI )
            {
                /* SelfSign 경우 KeyID 만 설정. */
                QString strVal = QString( "KEYID$%1").arg( getHexString( &binKeyID ) );
                profileExt.setValue( strVal );
                /*
                Need to support ISSUER and SERIAL
                */
            }

            transExtInfoFromDBRec( &sExtInfo, profileExt );
            JS_PKI_addExtensionInfoList( &pExtInfoList, &sExtInfo );
        }
    }

 //   nAlg = getKeyType( strAlg, strParam );

    if( isPKCS11Private( strAlg ) == true )
    {
        if( manApplet->settingsMgr()->PKCS11Use() == false )
        {
            manApplet->warningBox( tr("No PKCS11 settings"), this );
            ret = -1;
            goto end;
        }

        JP11_CTX *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        BIN binID = {0,0};

        if( pP11CTX == NULL )
        {
            manApplet->warningBox( tr("PKCS11 library was not loaded"), this );
            ret = -1;
            goto end;
        }

        ret = getP11Session( pP11CTX, nSlotID, strPIN );
        if( ret != 0 )
        {
            manApplet->warningBox( tr( "Failed to fetch session:%1 ").arg( ret ), this);
            ret = -1;
            goto end;
        }

        JS_BIN_decodeHex( keyRec.getPrivateKey().toStdString().c_str(), &binID );

        manApplet->log( QString( "ID : %1").arg( getHexString(&binID)));

        ret = JS_PKI_makeCSRByP11(
                                   strHash.toStdString().c_str(),
                                   strDN.toStdString().c_str(),
                                   strChallenge.length() > 0 ? strChallenge.toStdString().c_str() : NULL,
                                strUnstructuredName.length() > 0 ? strUnstructuredName.toStdString().c_str() : NULL,
                                   &binID,
                                   &binPubKey,
                                   pExtInfoList,
                                   pP11CTX,
                                   &binCSR );

        JS_BIN_reset( &binID );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
    }
    else if( isKMIPPrivate( strAlg ) == true )
    {
        if( manApplet->settingsMgr()->KMIPUse() == 0 )
            goto end;

        SSL_CTX *pCTX = NULL;
        SSL *pSSL = NULL;
        Authentication  *pAuth = NULL;
        BIN binID = {0,0};

        JS_BIN_decodeHex( keyRec.getPrivateKey().toStdString().c_str(), &binID );

        ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );

        if( ret == 0 )
        {
            ret = JS_PKI_makeCSRByKMIP(
                                        strHash.toStdString().c_str(),
                                        strDN.toStdString().c_str(),
                                        strChallenge.length() > 0 ? strChallenge.toStdString().c_str() : NULL,
                                       strUnstructuredName.length() > 0 ? strUnstructuredName.toStdString().c_str() : NULL,
                                        &binID,
                                        &binPubKey,
                                        pExtInfoList,
                                        pSSL,
                                        pAuth,
                                        &binCSR );
        }

        if( pSSL ) JS_SSL_clear( pSSL );
        if( pCTX ) JS_SSL_finish( &pCTX );
        if( pAuth )
        {
            JS_KMS_resetAuthentication( pAuth );
            JS_free( pAuth );
        }
        JS_BIN_reset( &binID );
    }
    else
    {
        manApplet->getPriKey( keyRec.getPrivateKey(), &binPri );

        ret = JS_PKI_makeCSR( strHash.length() ? strHash.toStdString().c_str() : NULL,
                              strDN.toStdString().c_str(),
                              strChallenge.length() > 0 ? strChallenge.toStdString().c_str() : NULL,
                              strUnstructuredName.length() > 0 ? strUnstructuredName.toStdString().c_str() : NULL,
                              &binPri,
                              pExtInfoList,
                              &binCSR );
    }


    if( ret != 0 )
    {
        manApplet->warnLog( tr( "Failed to create CSR : %1" ).arg(JERR(ret)), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCSR, &pHexCSR );

    if( strAlg == JS_PKI_KEY_NAME_EDDSA || strAlg == JS_PKI_KEY_NAME_ML_DSA || strAlg == JS_PKI_KEY_NAME_SLH_DSA )
        strHash = "NA";

    reqRec.setName( strName );
    reqRec.setRegTime( time(NULL) );
    reqRec.setCSR( QString(pHexCSR) );
    reqRec.setDN( strDN );
    reqRec.setHash( strHash );
    reqRec.setKeyNum( keyRec.getNum() );
    reqRec.setStatus(0);

    ret = dbMgr->addReqRec( reqRec );
    if( ret != 0 )
    {
        manApplet->warnLog( tr("Failed to save DB : %1").arg( JERR(ret) ), this );
        goto end;
    }


    dbMgr->modKeyPairStatus( keyRec.getNum(), JS_REC_STATUS_USED );
    if( manApplet->isPRO() ) addAudit( dbMgr, JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_CSR, strDN );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binPubKey );
    JS_BIN_reset( &binKeyID );

    if( pHexCSR ) JS_free( pHexCSR );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    if( ret == JSR_OK )
    {
        manApplet->mainWindow()->createRightRequestList();
        manApplet->messageBox( tr("CSR created"), this );

        if( mUseExtensionCheck->isChecked() == true )
        {
            QString strDefault = QString( "%1:%2" ).arg( mUseExtensionCheck->isChecked() ).arg( mProfileNumText->text().toInt());
            setDefault( strDefault );
        }
        else
        {
            setDefault( "" );
        }

        QDialog::accept();
    }
}

void MakeReqDlg::keyNumChanged()
{
    int nNum = mKeyNumText->text().toInt();
    KeyPairRec keyRec;

    int ret = manApplet->dbMgr()->getKeyPairRec( nNum, keyRec );
    if( ret != 0 )
    {
        mKeyNameText->clear();
        return;
    }

    mKeyNameText->setText( keyRec.getName() );
    mAlgorithmText->setText( keyRec.getAlg() );
    mOptionText->setText( keyRec.getParam() );

    mOptionLabel->setText( getParamLabel( keyRec.getAlg()));

    if( mOptionText->text() == "SM2" )
        mHashCombo->setCurrentText( "SM3" );

    if( keyRec.getAlg() == JS_PKI_KEY_NAME_EDDSA || keyRec.getAlg() == JS_PKI_KEY_NAME_ML_DSA || keyRec.getAlg() == JS_PKI_KEY_NAME_SLH_DSA )
    {
        mHashLabel->setEnabled( false );
        mHashCombo->setEnabled( false );
    }
    else
    {
        mHashLabel->setEnabled( true );
        mHashCombo->setEnabled( true );
    }

    QString strTitle = keyRec.getName();
    strTitle += "_CSR";
    mNameText->setText( strTitle );


    QString strDN = QString( "CN=%1").arg( keyRec.getName() );
    if( manApplet->settingsMgr()->baseDN().length() > 1 )
    {
        strDN += ",";
        strDN += manApplet->settingsMgr()->baseDN();
    }

    mDNText->setText( strDN );
}

void MakeReqDlg::profileNumChanged()
{
    int nNum = mProfileNumText->text().toInt();
    CertProfileRec profileRec;

    int ret = manApplet->dbMgr()->getCertProfileRec( nNum, profileRec );
    if( ret != 0 )
    {
        mProfileNumText->clear();
        return;
    }

    mProfileNameText->setText( profileRec.getName() );
}

void MakeReqDlg::clickRSA()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_RSA );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kRSAOptionList );
    mNewOptionCombo->setCurrentText( "2048" );
    mNewExponentText->setEnabled(true);
    mNewExponentLabel->setEnabled(true);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(true);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(true);
}

void MakeReqDlg::clickECDSA()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_ECDSA );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kECCOptionList );
    mNewOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
    mNewExponentText->setEnabled(false);
    mNewExponentLabel->setEnabled(false);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(true);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(true);
}

void MakeReqDlg::clickDSA()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_DSA );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kDSAOptionList );
    mNewOptionCombo->setCurrentText( "2048" );
    mNewExponentText->setEnabled(false);
    mNewExponentLabel->setEnabled(false);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(true);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(true);
}

void MakeReqDlg::clickEdDSA()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_EDDSA );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kEdDSAOptionList );
    mNewExponentText->setEnabled(false);
    mNewExponentLabel->setEnabled(false);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(false);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(true);
}

void MakeReqDlg::clickSM2()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_SM2 );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItem( "SM2" );
    mNewOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
    mNewExponentText->setEnabled(false);
    mNewExponentLabel->setEnabled(false);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(true);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(false);
}

void MakeReqDlg::clickML_DSA()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_ML_DSA );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kML_DSAOptionList );
    mNewExponentText->setEnabled(false);
    mNewExponentLabel->setEnabled(false);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(false);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(false);
}

void MakeReqDlg::clickSLH_DSA()
{
    QString strParamLabel = getParamLabel( JS_PKI_KEY_NAME_SLH_DSA );

    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kSLH_DSAOptionList );
    mNewExponentText->setEnabled(false);
    mNewExponentLabel->setEnabled(false);
    mNewOptionLabel->setText( strParamLabel );
    mHashCombo->setEnabled(false);

    if( manApplet->P11CTX() ) mPKCS11Check->setEnabled(false);
}

void MakeReqDlg::checkPKCS11()
{
    if( manApplet->isLicense() == true )
    {
        bool bVal = mPKCS11Check->isChecked();

        mEdDSARadio->setEnabled( !bVal );
        mSM2Radio->setEnabled( !bVal );
    }
}

void MakeReqDlg::checkKMIP()
{
    if( manApplet->isLicense() == true )
    {
        bool bVal = mKMIPCheck->isChecked();

        mDSARadio->setEnabled( !bVal );
        mEdDSARadio->setEnabled( !bVal );
        mSM2Radio->setEnabled( !bVal );
    }
}

void MakeReqDlg::clickSelectKeyPair()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select KeyPair" ));
    caMan.setMode( CAManModeSelectKeyPair );

    if( caMan.exec() == QDialog::Accepted )
    {
        mKeyNumText->setText( QString("%1").arg( caMan.getNum() ));
    }
}

void MakeReqDlg::clickSelectProfile()
{
    ProfileManDlg profileMan;
    profileMan.setTitle( tr( "Select a profile" ));
    profileMan.setMode( ProfileManModeSelectCSRProfile );

    if( profileMan.exec() == QDialog::Accepted )
    {
        mProfileNumText->setText( QString("%1").arg( profileMan.getNum() ));
    }
}

void MakeReqDlg::clickViewProfile()
{
    QString strNum = mProfileNumText->text();
    if( strNum.length() < 1 )
    {
        manApplet->warningBox( tr( "No profile selected" ), this );
        return;
    }

    ViewCertProfileDlg certProfile;
    certProfile.setProfile( strNum.toInt());
    certProfile.exec();
}

void MakeReqDlg::newOptionChanged(int index )
{
    if( mNewOptionCombo->currentText() == "SM2" )
        mHashCombo->setCurrentText( "SM3" );
}

void MakeReqDlg::checkGenKeyPair()
{
    bool bVal = mGenKeyPairCheck->isChecked();

    if( bVal )
    {
        mKeyInfoTab->setCurrentIndex(1);
        mKeyInfoTab->setTabEnabled(1, true );
        mKeyInfoTab->setTabEnabled(0, false);

        QString strName = mNameText->text();

        if( mNewKeyNameText->text().length() < 1 )
        {
            if( strName.length() > 0 )
            {
                strName += "_keyPair";
                mNewKeyNameText->setText( strName );
                mNewKeyNameText->setSelection(0, strName.length());
            }
        }
    }
    else
    {
        mKeyInfoTab->setCurrentIndex(0);
        mKeyInfoTab->setTabEnabled(0, true);
        mKeyInfoTab->setTabEnabled(1, false );
    }
}

void MakeReqDlg::checkExtension()
{
    bool bVal = mUseExtensionCheck->isChecked();

    mProfileNameText->setEnabled( bVal );
    mProfileNumText->setEnabled( bVal );
    mProfileNameLabel->setEnabled( bVal );
    mSelectProfileBtn->setEnabled( bVal );
    mViewProfileBtn->setEnabled( bVal );
}

void MakeReqDlg::clickMakeDN()
{
    QString strDN = mDNText->text();

    MakeDNDlg makeDNDlg;
    makeDNDlg.setDN( strDN );

    if( makeDNDlg.exec() == QDialog::Accepted )
    {
        QString strDN = makeDNDlg.getDN();
        mDNText->setText( strDN );
    }
}

void MakeReqDlg::initUI()
{
    mKeyInfoTab->setTabEnabled( 1, false );
    checkExtension();

    mKeyNameText->setPlaceholderText( tr( "Select a keypair from CA Man" ));

    QString strDefault = getDefault();

    QStringList listDefault = strDefault.split( ":" );
    if( listDefault.size() > 0 )
    {
        mExtensionSetDefaultCheck->setChecked(true);
        mUseExtensionCheck->setChecked( listDefault.at(0).toInt());
        checkExtension();
    }

    if( listDefault.size() > 1 )
    {
        mProfileNumText->setText( QString( "%1" ).arg( listDefault.at(1).toInt()));
        profileNumChanged();
    }
}

void MakeReqDlg::setDefault( const QString strDefault )
{
    QSettings sets;
    sets.beginGroup( kEnvTempGroup );
    sets.setValue( sUseExtension, strDefault );
    sets.endGroup();
}

const QString MakeReqDlg::getDefault()
{
    QString strDefault;

    QSettings sets;
    sets.beginGroup( kEnvTempGroup );
    strDefault = sets.value( sUseExtension, "" ).toString();
    sets.endGroup();

    return strDefault;
}
