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

static QStringList sMechList = { kMechRSA, kMechEC, kMechEdDSA, kMechDSA };

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

    if( manApplet->settingsMgr()->PKCS11Use() == false )
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

    /*
    if( manApplet->settingsMgr()->PKCS11Use() )
    {
        mMechCombo->addItem( kMechPKCS11_RSA );
        mMechCombo->addItem( kMechPKCS11_EC );
        mMechCombo->addItem( kMechPKCS11_DSA );
    }

    if( manApplet->settingsMgr()->KMIPUse() )
    {
        mMechCombo->addItem( kMechKMIP_RSA );
        mMechCombo->addItem( kMechKMIP_EC );
    }
    */

    mExponentText->setText( QString( "65537" ) );
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
            strMech = kMechRSA;
    }
    else if( mECDSARadio->isChecked() )
    {
        if( mPKCS11Check->isChecked() )
            strMech = kMechPKCS11_EC;
        else if( mKMIPCheck->isChecked() )
            strMech = kMechKMIP_EC;
        else
            strMech = kMechEC;
    }
    else if( mDSARadio->isChecked() )
    {
        if( mPKCS11Check->isChecked() )
            strMech = kMechPKCS11_DSA;
        else
            strMech = kMechDSA;
    }
    else if( mSM2Radio->isChecked() )
    {
        strMech = kMechSM2;
    }
    else if( mEdDSARadio->isChecked() )
    {
        strMech = kMechEdDSA;
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

    if( strMech == kMechRSA )
    {
        int nKeySize = strParam.toInt();
        int nExponent = mExponentText->text().toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
    }
    else if( strMech == kMechDSA )
    {
        int nKeySize = strParam.toInt();

        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &binPub, &binPri );
    }
    else if( strMech == kMechEC )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strMech == kMechSM2 )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strMech == kMechEdDSA )
    {
        int nParam = 0;

        if( strParam == kParamEd25519 )
            nParam = JS_PKI_KEY_TYPE_ED25519;
        else if( strParam == kParamEd448 )
            nParam = JS_PKI_KEY_TYPE_ED448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
    }
    else if( isPKCS11Private( strMech ) == true )
    {
        int ret = 0;
        int nIndex = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        CK_SESSION_HANDLE hSession = getP11Session( (JP11_CTX *)manApplet->P11CTX(), nIndex, strPIN );

        if( hSession < 0 )
        {
            manApplet->elog( "failed to get PKCS11 Session" );
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
    mOptionCombo->clear();

    mOptionCombo->addItems(kRSAOptionList);
    mOptionCombo->setCurrentText( "2048" );
    mExponentLabel->setEnabled(true);
    mExponentText->setEnabled(true);
    mOptionLabel->setText( "Key size");
}

void NewKeyDlg::clickECDSA()
{
    mOptionCombo->clear();

    mOptionCombo->addItems(kECCOptionList);
    mOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText("NamedCurve");
}

void NewKeyDlg::clickDSA()
{
    mOptionCombo->clear();

    mOptionCombo->addItems(kDSAOptionList);
    mOptionCombo->setCurrentText( "2048" );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( "Key size");
}

void NewKeyDlg::clickEdDSA()
{
    mOptionCombo->clear();

    mOptionCombo->addItems( kEdDSAOptionList );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText( "NamedCurve" );
}

void NewKeyDlg::clickSM2()
{
    mOptionCombo->clear();

    mOptionCombo->addItem( "SM2" );
    mOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
    mExponentLabel->setEnabled(false);
    mExponentText->setEnabled(false);
    mOptionLabel->setText("NamedCurve");
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
