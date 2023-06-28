#include "js_pki.h"

#include "man_applet.h"
#include "db_mgr.h"
#include "pri_key_info_dlg.h"


PriKeyInfoDlg::PriKeyInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    key_num_ = -1;
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mRSA_NText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_N(const QString&)));
    connect( mRSA_EText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_E(const QString&)));
    connect( mRSA_DText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_D(const QString&)));
    connect( mRSA_PText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_P(const QString&)));
    connect( mRSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_Q(const QString&)));
    connect( mRSA_DMP1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMP1(const QString&)));
    connect( mRSA_DMQ1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMQ1(const QString&)));
    connect( mRSA_IQMPText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_IQMP(const QString&)));

    connect( mECC_GroupText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_Group(const QString&)));
    connect( mECC_PubXText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_PubX(const QString&)));
    connect( mECC_PubYText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_PubY(const QString&)));
    connect( mECC_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_Private(const QString&)));
}

PriKeyInfoDlg::~PriKeyInfoDlg()
{

}

void PriKeyInfoDlg::setKeyNum( int key_num )
{
    key_num_ = key_num;
}

void PriKeyInfoDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr == NULL ) return;

    KeyPairRec keyPair;

    mKeyTab->setTabEnabled(0, false);
    mKeyTab->setTabEnabled(1, false);
    mKeyTab->setTabEnabled(2, false);
    mKeyTab->setTabEnabled(3, false);

    dbMgr->getKeyPairRec( key_num_, keyPair );

    if( keyPair.getAlg() == "RSA" )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAPriKey( keyPair.getPrivateKey() );
    }
    else if( keyPair.getAlg() == "EC" )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCPriKey( keyPair.getPrivateKey() );
    }
    else if( keyPair.getAlg() == "DSA" )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
    }
    else
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
    }
}

void PriKeyInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void PriKeyInfoDlg::setRSAPriKey( const QString& strPriVal )
{
    int ret = 0;
    JRSAKeyVal  sRSAKey;
    BIN binPri = {0,0};

    if( strPriVal.length() < 1 ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    JS_BIN_decodeHex( strPriVal.toStdString().c_str(), &binPri );
    ret = JS_PKI_getRSAKeyVal( &binPri, &sRSAKey );

    if( ret == 0 )
    {
        mRSA_NText->setText( sRSAKey.pN );
        mRSA_EText->setText( sRSAKey.pE );
        mRSA_DText->setText( sRSAKey.pD );
        mRSA_PText->setText( sRSAKey.pP );
        mRSA_QText->setText( sRSAKey.pQ );
        mRSA_DMP1Text->setText( sRSAKey.pDMP1 );
        mRSA_DMQ1Text->setText( sRSAKey.pDMQ1 );
        mRSA_IQMPText->setText( sRSAKey.pIQMP );
    }

    JS_BIN_reset( &binPri );
    JS_PKI_resetRSAKeyVal( &sRSAKey );
}

void PriKeyInfoDlg::setECCPriKey( const QString& strPriVal )
{
    int ret = 0;
    JECKeyVal sECKey;
    BIN binPri = {0,0};

    if( strPriVal.length() < 1 ) return;

    memset( &sECKey, 0x00, sizeof(sECKey));

    JS_BIN_decodeHex( strPriVal.toStdString().c_str(), &binPri );
    ret = JS_PKI_getECKeyVal( &binPri, &sECKey );

    if( ret == 0 )
    {
        mECC_GroupText->setText( sECKey.pGroup );
        mECC_PubXText->setText( sECKey.pPubX );
        mECC_PubYText->setText( sECKey.pPubY );
        mECC_PrivateText->setText( sECKey.pPrivate );
    }

    JS_BIN_reset( &binPri );
    JS_PKI_resetECKeyVal( &sECKey );
}

void PriKeyInfoDlg::changeRSA_N( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_NLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_E( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_ELenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_D( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_DLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_P( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_PLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_Q( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_QLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_DMP1( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_DMP1LenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_DMQ1( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_DMQ1LenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_IQMP( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_IQMPLenText->setText( QString("%1").arg(nLen));
}


void PriKeyInfoDlg::changeECC_Group( const QString& text )
{
    int nLen = text.length() / 2;
    mECC_GroupLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeECC_PubX( const QString& text )
{
    int nLen = text.length() / 2;
    mECC_PubXLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeECC_PubY( const QString& text )
{
    int nLen = text.length() / 2;
    mECC_PubYLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeECC_Private( const QString& text )
{
    int nLen = text.length() / 2;
    mECC_PrivateLenText->setText( QString("%1").arg(nLen));
}

