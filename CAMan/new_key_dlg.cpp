#include "new_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_bin.h"
#include "db_mgr.h"
#include "key_pair_rec.h"

static QStringList sMechList = { "RSA", "ECC" };
static QStringList sRSAOptionList = { "1024", "2048", "3072", "4096" };
static QStringList sECCOptionList = {
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192k1", "secp224k1", "secp224r1",
    "secp256k1", "secp384r1", "secp521r1", "sect113r1", "sect113r2",
    "sect131r1", "sect131r2", "sect163k1", "sect163r1", "sect163r2",
    "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1",
    "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1",
    "sect571r1"
};

NewKeyDlg::NewKeyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mMechCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(mechChanged(int)));
}

NewKeyDlg::~NewKeyDlg()
{

}

void NewKeyDlg::showEvent(QShowEvent *event)
{
    initUI();
}

void NewKeyDlg::initUI()
{
    mMechCombo->addItems(sMechList);
    mOptionCombo->addItems(sRSAOptionList);
}

void NewKeyDlg::accept()
{
    int ret = 0;
    QString strName = mNameText->text();
    KeyPairRec keyPairRec;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("You have to write name"), this );
        mNameText->setFocus();
        return;
    }

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    BIN binPub2 = {0,0};
    char *pPriHex = NULL;
    char *pPubHex = NULL;

    if( mMechCombo->currentIndex() == 0 )
    {
        int nKeySize = mOptionCombo->currentText().toInt();
        int nExponent = mExponentText->text().toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPub2, &binPri );
    }
    else if( mMechCombo->currentIndex() == 1 )
    {
        int nGroupID = JS_PKI_getNidFromSN( mOptionCombo->currentText().toStdString().c_str() );
        ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPub2, &binPri );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to generate key pairs"), this );
        goto end;
    }

    JS_BIN_encodeHex( &binPri, &pPriHex );
    JS_BIN_encodeHex( &binPub2, &pPubHex );

    keyPairRec.setAlg( mMechCombo->currentText() );
    keyPairRec.setName( strName );
    keyPairRec.setParam( mOptionCombo->currentText() );
    keyPairRec.setPublicKey( pPubHex );
    keyPairRec.setPrivateKey( pPriHex );
    keyPairRec.setStatus(0);

    dbMgr->addKeyPairRec( keyPairRec );

end:
    JS_BIN_reset(&binPri);
    JS_BIN_reset(&binPub);
    JS_BIN_reset(&binPub2);
    if( pPriHex ) JS_free( pPriHex );
    if( pPubHex ) JS_free( pPubHex );

    if( ret == 0 ) QDialog::accept();
}

void NewKeyDlg::mechChanged(int index )
{
    mOptionCombo->clear();

    if( index == 0 )
    {
        mOptionCombo->addItems(sRSAOptionList);
        mExponentText->setEnabled(true);
        mOptionLabel->setText( "Key size");
    }
    else if( index == 1 )
    {
        mOptionCombo->addItems(sECCOptionList);
        mExponentText->setEnabled(false);
        mOptionLabel->setText("NamedCurve");
    }
}
