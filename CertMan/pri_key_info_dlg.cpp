#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"

#include "man_applet.h"
#include "db_mgr.h"
#include "pri_key_info_dlg.h"


PriKeyInfoDlg::PriKeyInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    key_num_ = -1;
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    connect( mRSA_NText, SIGNAL(textChanged()), this, SLOT(changeRSA_N()));
    connect( mRSA_EText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_E(const QString&)));
    connect( mRSA_DText, SIGNAL(textChanged()), this, SLOT(changeRSA_D()));
    connect( mRSA_PText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_P(const QString&)));
    connect( mRSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_Q(const QString&)));
    connect( mRSA_DMP1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMP1(const QString&)));
    connect( mRSA_DMQ1Text, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_DMQ1(const QString&)));
    connect( mRSA_IQMPText, SIGNAL(textChanged(const QString&)), this, SLOT(changeRSA_IQMP(const QString&)));

    connect( mECC_GroupText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_Group(const QString&)));
    connect( mECC_PubXText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_PubX(const QString&)));
    connect( mECC_PubYText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_PubY(const QString&)));
    connect( mECC_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeECC_Private(const QString&)));

    connect( mDSA_GText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_G(const QString&)));
    connect( mDSA_PText, SIGNAL(textChanged()), this, SLOT(changeDSA_P()));
    connect( mDSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Q(const QString&)));
    connect( mDSA_PublicText, SIGNAL(textChanged()), this, SLOT(changeDSA_Public()));
    connect( mDSA_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Private(const QString&)));

    connect( mEdDSA_RawPublicText, SIGNAL(textChanged(const QString&)), this, SLOT(changeEdDSA_RawPublic(const QString&)));
    connect( mEdDSA_RawPrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeEdDSA_RawPrivate(const QString&)));
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
    BIN binPri = {0,0};

    mKeyTab->setTabEnabled(0, false);
    mKeyTab->setTabEnabled(1, false);
    mKeyTab->setTabEnabled(2, false);
    mKeyTab->setTabEnabled(3, false);

    dbMgr->getKeyPairRec( key_num_, keyPair );

    if( manApplet->isPasswd() )
        manApplet->getDecPriBIN( keyPair.getPrivateKey(), &binPri );
    else
        JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

    if( keyPair.getAlg() == "RSA" )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAPriKey( &binPri );
    }
    else if( keyPair.getAlg() == "EC" )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCPriKey( &binPri );
    }
    else if( keyPair.getAlg() == "DSA" )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAPriKey( &binPri );
    }
    else
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAPriKey( keyPair.getParam(), &binPri );
    }

    JS_BIN_reset( &binPri );
}

void PriKeyInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void PriKeyInfoDlg::setRSAPriKey( const BIN *pPriKey )
{
    int ret = 0;
    JRSAKeyVal  sRSAKey;

    if( pPriKey == NULL || pPriKey->nLen <= 0 ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    ret = JS_PKI_getRSAKeyVal( pPriKey, &sRSAKey );

    if( ret == 0 )
    {
        mRSA_NText->setPlainText( sRSAKey.pN );
        mRSA_EText->setText( sRSAKey.pE );
        mRSA_DText->setPlainText( sRSAKey.pD );
        mRSA_PText->setText( sRSAKey.pP );
        mRSA_QText->setText( sRSAKey.pQ );
        mRSA_DMP1Text->setText( sRSAKey.pDMP1 );
        mRSA_DMQ1Text->setText( sRSAKey.pDMQ1 );
        mRSA_IQMPText->setText( sRSAKey.pIQMP );
    }

    JS_PKI_resetRSAKeyVal( &sRSAKey );
}

void PriKeyInfoDlg::setECCPriKey( const BIN *pPriKey )
{
    int ret = 0;
    JECKeyVal sECKey;

    if( pPriKey == NULL || pPriKey->nLen <= 0 ) return;

    memset( &sECKey, 0x00, sizeof(sECKey));

    ret = JS_PKI_getECKeyVal( pPriKey, &sECKey );

    if( ret == 0 )
    {
        mECC_GroupText->setText( sECKey.pGroup );
        mECC_PubXText->setText( sECKey.pPubX );
        mECC_PubYText->setText( sECKey.pPubY );
        mECC_PrivateText->setText( sECKey.pPrivate );
    }

    JS_PKI_resetECKeyVal( &sECKey );
}

void PriKeyInfoDlg::setDSAPriKey( const BIN *pPriKey )
{
    int ret = 0;
    JDSAKeyVal sDSAKey;

    if( pPriKey == NULL || pPriKey->nLen <= 0 ) return;

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    ret = JS_PKI_getDSAKeyVal( pPriKey, &sDSAKey );

    if( ret == 0 )
    {
        mDSA_GText->setText( sDSAKey.pG );
        mDSA_PText->setPlainText( sDSAKey.pP );
        mDSA_QText->setText( sDSAKey.pQ );
        mDSA_PublicText->setPlainText( sDSAKey.pPublic );
        mDSA_PrivateText->setText( sDSAKey.pPrivate );
    }

    JS_PKI_resetDSAKeyVal( &sDSAKey );
}

void PriKeyInfoDlg::setEdDSAPriKey( const QString& strParam, const BIN *pPriKey )
{
    int ret = 0;
    int nType = 0;
    JRawKeyVal sRawKeyVal;

    if( pPriKey == NULL || pPriKey->nLen <= 0 ) return;

    if( strParam == "Ed25519" )
        nType = JS_PKI_KEY_TYPE_ED25519;
    else
        nType = JS_PKI_KEY_TYPE_ED448;

    memset( &sRawKeyVal, 0x00, sizeof(sRawKeyVal));
    ret = JS_PKI_getRawKeyVal( nType, pPriKey, &sRawKeyVal );

    if( ret == 0 )
    {
        mEdDSA_NameText->setText( sRawKeyVal.pName );
        mEdDSA_RawPublicText->setText( sRawKeyVal.pPub );
        mEdDSA_RawPrivateText->setText( sRawKeyVal.pPri );
    }

    JS_PKI_resetRawKeyVal( &sRawKeyVal );
}

void PriKeyInfoDlg::changeRSA_N()
{
    QString strN = mRSA_NText->toPlainText();
    int nLen = strN.length() / 2;
    mRSA_NLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_E( const QString& text )
{
    int nLen = text.length() / 2;
    mRSA_ELenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeRSA_D()
{
    QString strD = mRSA_DText->toPlainText();
    int nLen = strD.length() / 2;
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

void PriKeyInfoDlg::changeDSA_G( const QString& text )
{
    int nLen = text.length() / 2;
    mDSA_GLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeDSA_P()
{
    QString strP = mDSA_PText->toPlainText();
    int nLen = strP.length() / 2;
    mDSA_PLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeDSA_Q( const QString& text )
{
    int nLen = text.length() / 2;
    mDSA_QLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeDSA_Public()
{
    QString strPublic = mDSA_PublicText->toPlainText();
    int nLen = strPublic.length() / 2;
    mDSA_PublicLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeDSA_Private( const QString& text )
{
    int nLen = text.length() / 2;
    mDSA_PrivateLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPublic( const QString& text )
{
    int nLen = text.length() / 2;
    mEdDSA_RawPublicLenText->setText( QString("%1").arg(nLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPrivate( const QString& text )
{
    int nLen = text.length() / 2;
    mEdDSA_RawPrivateLenText->setText( QString("%1").arg(nLen));
}
