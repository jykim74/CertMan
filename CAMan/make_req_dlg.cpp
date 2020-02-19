#include "make_req_dlg.h"
#include "ui_make_req_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "key_pair_rec.h"
#include "req_rec.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "settings_mgr.h"
#include "commons.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };

MakeReqDlg::MakeReqDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mKeyNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyNameChanged(int)));

    initialize();
}

MakeReqDlg::~MakeReqDlg()
{

}

void MakeReqDlg::initialize()
{
    mHashCombo->addItems(sHashList);

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    key_list_.clear();
    dbMgr->getKeyPairList( 0, key_list_ );

    for( int i = 0; i < key_list_.size(); i++ )
    {
        KeyPairRec keyRec = key_list_.at(i);
        mKeyNameCombo->addItem( keyRec.getName() );
    }
}

void MakeReqDlg::accept()
{
    int nAlg = -1;
    int ret = 0;
    BIN binPri = {0,0};
    BIN binCSR = {0,0};
    char *pHexCSR = NULL;
    KeyPairRec keyRec;
    ReqRec reqRec;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert name"), this );
        mNameText->setFocus();
        return;
    }

    QString strDN = mDNText->text();

    if( strDN.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert DN"), this );
        mDNText->setFocus();
        return;
    }

    int keyIdx = mKeyNameCombo->currentIndex();
    keyRec = key_list_.at( keyIdx );
    QString strAlg = mAlgorithmText->text();
    QString strHash = mHashCombo->currentText();

    if( strAlg == "PKCS11_RSA" || strAlg == "PKCS11_ECC" )
    {
        JP11_CTX *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotID();
        BIN binPubKey = {0,0};

        CK_SESSION_HANDLE hSession = getP11Session( pP11CTX, nSlotID );
        if( hSession < 0 )
        {
            goto end;
        }

        if( strAlg == "PKCS11_RSA" )
            nAlg = JS_PKI_KEY_TYPE_RSA;
        else
            nAlg = JS_PKI_KEY_TYPE_ECC;

        JS_BIN_decodeHex( keyRec.getPublicKey().toStdString().c_str(), &binPubKey );

        ret = JS_PKI_makeCSRByP11( nAlg,
                                   strHash.toStdString().c_str(),
                                   strDN.toStdString().c_str(),
                                   &binPubKey,
                                   NULL,
                                   pP11CTX,
                                   hSession,
                                   &binCSR );

        JS_BIN_reset( &binPubKey );

        JS_PKCS11_Logout( pP11CTX, hSession );
        JS_PKCS11_CloseSession( pP11CTX, hSession );
    }
    else
    {
        if( mAlgorithmText->text() == "RSA" )
            nAlg = JS_PKI_KEY_TYPE_RSA;
        else {
            nAlg = JS_PKI_KEY_TYPE_ECC;
        }


        JS_BIN_decodeHex( keyRec.getPrivateKey().toStdString().c_str(), &binPri );
        ret = JS_PKI_makeCSR( nAlg, mHashCombo->currentText().toStdString().c_str(),
                        strDN.toStdString().c_str(),
                        &binPri,
                        NULL,
                        &binCSR );
    }


    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to make request"), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCSR, &pHexCSR );

    reqRec.setName( strName );
    reqRec.setCSR( QString(pHexCSR) );
    reqRec.setDN( strDN );
    reqRec.setHash( mHashCombo->currentText() );
    reqRec.setKeyNum( keyRec.getNum() );
    reqRec.setStatus(0);

    dbMgr->addReqRec( reqRec );
    dbMgr->modKeyPairStatus( keyRec.getNum(), 1 );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCSR );
    if( pHexCSR ) JS_free( pHexCSR );

    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightRequestList();
        QDialog::accept();
    }
}

void MakeReqDlg::keyNameChanged(int index)
{
    KeyPairRec keyRec = key_list_.at(index);

    mAlgorithmText->setText( keyRec.getAlg() );
    mOptionText->setText( keyRec.getParam() );

    if( keyRec.getAlg() == "RSA" )
        mOptionLabel->setText( "Key Size" );
    else {
        mOptionLabel->setText( "NamedCurve" );
    }
}

void MakeReqDlg::initUI()
{

}


