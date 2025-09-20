/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "new_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"
#include "js_bin.h"
#include "db_mgr.h"
#include "key_pair_rec.h"
#include "settings_mgr.h"
#include "pin_dlg.h"
#include "js_pkcs11.h"
#include "js_kms.h"
#include "js_gen.h"
#include "js_define.h"
#include "commons.h"
#include "js_pqc.h"

static QStringList sMechList = {
    JS_PKI_KEY_NAME_RSA, JS_PKI_KEY_NAME_ECDSA, JS_PKI_KEY_NAME_DSA,
    JS_PKI_KEY_NAME_EDDSA, JS_PKI_KEY_NAME_ML_DSA, JS_PKI_KEY_NAME_SLH_DSA
};

NewKeyDlg::NewKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
//    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));

    connect( mRSARadio, SIGNAL(clicked()), this, SLOT(clickRSA()));
    connect( mECDSARadio, SIGNAL(clicked()), this, SLOT(clickECDSA()));
    connect( mDSARadio, SIGNAL(clicked()), this, SLOT(clickDSA()));
    connect( mEdDSARadio, SIGNAL(clicked()), this, SLOT(clickEdDSA()));
    connect( mSM2Radio, SIGNAL(clicked()), this, SLOT(clickSM2()));
    connect( mML_DSARadio, SIGNAL(clicked()), this, SLOT(clickML_DSA()));
    connect( mSLH_DSARadio, SIGNAL(clicked()), this, SLOT(clickSLH_DSA()));

    connect( mPKCS11Check, SIGNAL(clicked()), this, SLOT(checkPKCS11()));
    connect( mKMIPCheck, SIGNAL(clicked()), this, SLOT(checkKMIP()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

NewKeyDlg::~NewKeyDlg()
{

}

void NewKeyDlg::initialize()
{
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
        mSM2Radio->setEnabled( false );
    }

    mRSARadio->click();
}

void NewKeyDlg::initUI()
{
    // mMechCombo->addItems(sMechList);
    mOptionCombo->addItems(kRSAOptionList);
    mOptionCombo->setCurrentText( "2048" );
    mExponentText->setText( QString( "65537" ) );

    mNameText->setPlaceholderText( tr( "Enter a key name" ));
}

const QString NewKeyDlg::getMechanism()
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
            strMech = kMechPKCS11_EC;
        else if( mKMIPCheck->isChecked() )
            strMech = kMechKMIP_EC;
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
    else if( mSM2Radio->isChecked() )
    {
        strMech = JS_PKI_KEY_NAME_SM2;
    }
    else if( mEdDSARadio->isChecked() )
    {
        strMech = JS_PKI_KEY_NAME_EDDSA;
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

void NewKeyDlg::accept()
{
    int ret = 0;
    QString strName = mNameText->text();
    KeyPairRec keyPairRec;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("You have to write name"), this );
        mNameText->setFocus();
        return;
    }

    BIN binPri = {0,0};
    BIN binPub = {0,0};

    char *pPriHex = NULL;
    char *pPubHex = NULL;

//    QString strMech = mMechCombo->currentText();
    QString strMech = getMechanism();
    QString strParam = mOptionCombo->currentText();

    if( strMech == JS_PKI_KEY_NAME_RSA )
    {
        int nKeySize = strParam.toInt();
        int nExponent = mExponentText->text().toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
    }
    else if( strMech == JS_PKI_KEY_NAME_DSA )
    {
        int nKeySize = strParam.toInt();

        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &binPub, &binPri );
    }
    else if( strMech == JS_PKI_KEY_NAME_ECDSA )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strMech == JS_PKI_KEY_NAME_SM2 )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strMech == JS_PKI_KEY_NAME_ML_DSA )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_ML_DSA_genKeyPair( nParam, &binPub, &binPri );
    }
    else if( strMech == JS_PKI_KEY_NAME_SLH_DSA )
    {
        int nParam = JS_PQC_param( strParam.toStdString().c_str() );
        ret = JS_SLH_DSA_genKeyPair( nParam, &binPub, &binPri );
    }
    else if( strMech == JS_PKI_KEY_NAME_EDDSA )
    {
        int nParam = 0;

        if( strParam == JS_EDDSA_PARAM_NAME_25519 )
            nParam = JS_EDDSA_PARAM_25519;
        else if( strParam == JS_EDDSA_PARAM_NAME_448 )
            nParam = JS_EDDSA_PARAM_448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
    }
    else if( isPKCS11Private( strMech ) == true )
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
            manApplet->elog( QString( "failed to get PKCS11 Session: %1" ).arg( ret ) );
            goto end;
        }

        ret = genKeyPairWithP11( (JP11_CTX *)manApplet->P11CTX(),
                                 mNameText->text(),
                                 strMech,
                                 mOptionCombo->currentText(),
                                 mExponentText->text().toInt(),
                                 &binPri,
                                 &binPub );

        JS_PKCS11_Logout( (JP11_CTX *)manApplet->P11CTX() );
        JS_PKCS11_CloseSession( (JP11_CTX *)manApplet->P11CTX() );
    }
    else if( isKMIPPrivate( strMech ) == true )
    {
        ret = genKeyPairWithKMIP(
                    manApplet->settingsMgr(),
                    strMech,
                    mOptionCombo->currentText(),
                    &binPri,
                    &binPub );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to generate key pairs"), this );
        goto end;
    }

    if( isInternalPrivate( strMech ) == true )
    {
        if( manApplet->isPasswd() )
        {
            QString strHex = manApplet->getEncPriHex( &binPri );
            keyPairRec.setPrivateKey( strHex );
        }
        else
        {
            JS_BIN_encodeHex( &binPri, &pPriHex );
            keyPairRec.setPrivateKey( pPriHex );
        }
    }
    else
    {
        JS_BIN_encodeHex( &binPri, &pPriHex );
        keyPairRec.setPrivateKey( pPriHex );
    }

    JS_BIN_encodeHex( &binPub, &pPubHex );

    keyPairRec.setAlg( strMech );
    keyPairRec.setRegTime( time(NULL) );
    keyPairRec.setName( strName );
    keyPairRec.setParam( mOptionCombo->currentText() );
    keyPairRec.setPublicKey( pPubHex );

    keyPairRec.setStatus(JS_REC_STATUS_NOT_USED);

    ret = dbMgr->addKeyPairRec( keyPairRec );
    if( ret != 0 ) goto end;

    if( manApplet->isPRO() ) addAudit( dbMgr, JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_KEY_PAIR, "" );

end:
    JS_BIN_reset(&binPri);
    JS_BIN_reset(&binPub);
    if( pPriHex ) JS_free( pPriHex );
    if( pPubHex ) JS_free( pPubHex );


    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightKeyPairList();
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "failed to generate key pair" ), this );
        QDialog::reject();
    }
}

void NewKeyDlg::clickRSA()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_RSA );
    mOptionCombo->clear();

    mOptionCombo->addItems(kRSAOptionList);
    mOptionCombo->setCurrentText( "2048" );
    mExponentLabel->setEnabled(true);
    mExponentText->setEnabled(true);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::clickECDSA()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_ECDSA );
    mOptionCombo->clear();

    mOptionCombo->addItems(kECCOptionList);
    mOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::clickDSA()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_DSA );
    mOptionCombo->clear();

    mOptionCombo->addItems(kDSAOptionList);
    mOptionCombo->setCurrentText( "2048" );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::clickEdDSA()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_EDDSA  );
    mOptionCombo->clear();

    mOptionCombo->addItems( kEdDSAOptionList );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::clickSM2()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_SM2  );
    mOptionCombo->clear();

    mOptionCombo->addItem( "SM2" );
    mOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::clickML_DSA()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_ML_DSA  );
    mOptionCombo->clear();

    mOptionCombo->addItems( kML_DSAOptionList );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::clickSLH_DSA()
{
    QString strOptionLabel = getParamLabel( JS_PKI_KEY_NAME_SLH_DSA  );
    mOptionCombo->clear();

    mOptionCombo->addItems( kSLH_DSAOptionList );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( strOptionLabel );
}

void NewKeyDlg::checkPKCS11()
{
    if( manApplet->isLicense() == true )
    {
        bool bVal = mPKCS11Check->isChecked();

        mEdDSARadio->setEnabled( !bVal );
        mSM2Radio->setEnabled( !bVal );
    }
}

void NewKeyDlg::checkKMIP()
{
    if( manApplet->isLicense() == true )
    {
        bool bVal = mKMIPCheck->isChecked();

        mDSARadio->setEnabled( !bVal );
        mEdDSARadio->setEnabled( !bVal );
        mSM2Radio->setEnabled( !bVal );
    }
}
