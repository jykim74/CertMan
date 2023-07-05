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
#include "commons.h"

static QStringList sMechList = { kMechRSA, kMechEC, kMechEdDSA, kMechDSA };

NewKeyDlg::NewKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));
    initialize();
}

NewKeyDlg::~NewKeyDlg()
{

}

void NewKeyDlg::initialize()
{

}

void NewKeyDlg::initUI()
{
    mMechCombo->addItems(sMechList);
    mOptionCombo->addItems(kRSAOptionList);
    mOptionCombo->setCurrentText( "2048" );

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

    mExponentText->setText( QString( "65537" ) );
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

    if( manApplet->isLicense() == false )
    {
        int nTotalCnt = dbMgr->getKeyPairCountAll();

        if( nTotalCnt >= JS_NO_LICENSE_KEYPAIR_LIMIT_COUNT )
        {
            manApplet->warningBox( tr( "You could not make key pair than max key count(%1) in no license")
                                   .arg( JS_NO_LICENSE_KEYPAIR_LIMIT_COUNT ), this );
            return;
        }
    }

    BIN binPri = {0,0};
    BIN binPub = {0,0};

    char *pPriHex = NULL;
    char *pPubHex = NULL;

    QString strMech = mMechCombo->currentText();

    if( strMech == kMechRSA )
    {
        int nKeySize = mOptionCombo->currentText().toInt();
        int nExponent = mExponentText->text().toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
    }
    else if( strMech == kMechDSA )
    {
        int nKeySize = mOptionCombo->currentText().toInt();

        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &binPub, &binPri );
    }
    else if( strMech == kMechEC )
    {
        int nGroupID = JS_PKI_getNidFromSN( mOptionCombo->currentText().toStdString().c_str() );
        ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPri );
    }
    else if( strMech == kMechEdDSA )
    {
        int nParam = 0;

        if( mOptionCombo->currentText() == "Ed25519" )
            nParam = JS_PKI_KEY_TYPE_ED25519;
        else if( mOptionCombo->currentText() == "Ed448" )
            nParam = JS_PKI_KEY_TYPE_ED448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
    }
    else if( strMech == kMechPKCS11_RSA || strMech == kMechPKCS11_EC || strMech == kMechPKCS11_DSA )
    {
        QString strPin;
        PinDlg  pinDlg;
        int ret = pinDlg.exec();

        if( ret == QDialog::Accepted )
        {
            strPin = pinDlg.getPinText();
//            ret = genKeyPairWithP11( strPin, &binPri, &binPub );
//            pP11CTX = (JP11_CTX *)manApplet->P11CTX();

            ret = genKeyPairWithP11( (JP11_CTX *)manApplet->P11CTX(),
                                     manApplet->settingsMgr()->slotID(),
                                     strPin,
                                     mNameText->text(),
                                     mMechCombo->currentText(),
                                     mOptionCombo->currentText(),
                                     mExponentText->text().toInt(),
                                     &binPri,
                                     &binPub );
        }
        else
        {
            ret = -1;
        }
    }
    else if( mMechCombo->currentText() == kMechKMIP_RSA || mMechCombo->currentText() == kMechKMIP_EC )
    {
        ret = genKeyPairWithKMIP(
                    manApplet->settingsMgr(),
                    mMechCombo->currentText(),
                    mOptionCombo->currentText(),
                    &binPri,
                    &binPub );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to generate key pairs"), this );
        goto end;
    }

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

    JS_BIN_encodeHex( &binPub, &pPubHex );

    keyPairRec.setAlg( mMechCombo->currentText() );
    keyPairRec.setRegTime( time(NULL) );
    keyPairRec.setName( strName );
    keyPairRec.setParam( mOptionCombo->currentText() );
    keyPairRec.setPublicKey( pPubHex );

    keyPairRec.setStatus(0);

    dbMgr->addKeyPairRec( keyPairRec );
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
}

void NewKeyDlg::mechChanged(int index )
{
    mOptionCombo->clear();
    QString strMech = mMechCombo->currentText();

    if( strMech == kMechRSA || strMech == kMechPKCS11_RSA || strMech == kMechKMIP_RSA )
    {
        mOptionCombo->addItems(kRSAOptionList);
        mOptionCombo->setCurrentText( "2048" );
        mExponentLabel->setEnabled(true);
        mExponentText->setEnabled(true);
        mOptionLabel->setText( "Key size");
    }
    else if( strMech == kMechEC || strMech == kMechPKCS11_EC )
    {
        mOptionCombo->addItems(kECCOptionList);
        mOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
        mExponentLabel->setEnabled(false);
        mExponentText->setEnabled(false);
        mOptionLabel->setText("NamedCurve");
    }
    else if( strMech == kMechKMIP_EC)
    {
        mOptionCombo->addItem( "prime256v1" );
        mExponentLabel->setEnabled(false);
        mExponentText->setEnabled(false);
        mOptionLabel->setText("NamedCurve");
    }
    else if( strMech == kMechEdDSA )
    {
        mOptionCombo->addItems( kEdDSAOptionList );
        mExponentLabel->setEnabled(false);
        mExponentText->setEnabled(false);
        mOptionLabel->setText( "NamedCurve" );
    }
    else if( strMech == kMechDSA || strMech == kMechPKCS11_DSA )
    {
        mOptionCombo->addItems(kDSAOptionList);
        mOptionCombo->setCurrentText( "2048" );
        mExponentLabel->setEnabled(false);
        mExponentText->setEnabled(false);
        mOptionLabel->setText( "Key size");
    }
}
