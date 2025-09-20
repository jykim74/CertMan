/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_tools.h"

#include "man_applet.h"
#include "db_mgr.h"
#include "pri_key_info_dlg.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "js_pkcs11.h"
#include "js_pki_tools.h"
#include "js_error.h"
#include "commons.h"


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

    connect( mECC_PubXText, SIGNAL(textChanged()), this, SLOT(changeECC_PubX()));
    connect( mECC_PubYText, SIGNAL(textChanged()), this, SLOT(changeECC_PubY()));
    connect( mECC_PrivateText, SIGNAL(textChanged()), this, SLOT(changeECC_Private()));

    connect( mDSA_GText, SIGNAL(textChanged()), this, SLOT(changeDSA_G()));
    connect( mDSA_PText, SIGNAL(textChanged()), this, SLOT(changeDSA_P()));
    connect( mDSA_QText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Q(const QString&)));
    connect( mDSA_PublicText, SIGNAL(textChanged()), this, SLOT(changeDSA_Public()));
    connect( mDSA_PrivateText, SIGNAL(textChanged(const QString&)), this, SLOT(changeDSA_Private(const QString&)));

    connect( mEdDSA_RawPublicText, SIGNAL(textChanged()), this, SLOT(changeEdDSA_RawPublic()));
    connect( mEdDSA_RawPrivateText, SIGNAL(textChanged()), this, SLOT(changeEdDSA_RawPrivate()));

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mGetPrivateKeyBtn, SIGNAL(clicked()), this, SLOT(clickGetPrivateKey()));
    connect( mGetPublicKeyBtn, SIGNAL(clicked()), this, SLOT(clickGetPublicKey()));
    connect( mInsertToHSMBtn, SIGNAL(clicked()), this, SLOT(clickInsertToHSM()));
    connect( mKeyPairCheckBtn, SIGNAL(clicked()), this, SLOT(clickKeyPairCheck()));

    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mRSATab->layout()->setSpacing(5);
    mRSATab->layout()->setMargin(5);
    mECCTab->layout()->setSpacing(5);
    mECCTab->layout()->setMargin(5);
    mDSATab->layout()->setSpacing(5);
    mDSATab->layout()->setMargin(5);
    mEdDSATab->layout()->setSpacing(5);
    mEdDSATab->layout()->setMargin(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PriKeyInfoDlg::~PriKeyInfoDlg()
{

}

void PriKeyInfoDlg::setKeyNum( int key_num )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    key_num_ = key_num;

    if( dbMgr == NULL ) return;
    dbMgr->getKeyPairRec( key_num, key_rec_ );
}

void PriKeyInfoDlg::initialize()
{
    mKeyTab->setTabEnabled(0, false);
    mKeyTab->setTabEnabled(1, false);
    mKeyTab->setTabEnabled(2, false);
    mKeyTab->setTabEnabled(3, false);

    clickGetPrivateKey();

    if( manApplet->settingsMgr()->PKCS11Use() == false )
        mInsertToHSMBtn->hide();
}

void PriKeyInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void PriKeyInfoDlg::setRSAKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JRSAKeyVal  sRSAKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));

    if( bPri == true )
        ret = JS_PKI_getRSAKeyVal( pKey, &sRSAKey );
    else
        ret = JS_PKI_getRSAKeyValFromPub( pKey, &sRSAKey );

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

void PriKeyInfoDlg::setECCKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JECKeyVal sECKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sECKey, 0x00, sizeof(sECKey));

    if( bPri == true )
        ret = JS_PKI_getECKeyVal( pKey, &sECKey );
    else
        ret = JS_PKI_getECKeyValFromPub( pKey, &sECKey );

    if( ret == 0 )
    {
        QString strSN = JS_PKI_getSNFromOID( sECKey.pCurveOID );
        mECC_CurveOIDText->setText( QString( "%1" ).arg(sECKey.pCurveOID) );
        mECC_CurveSNText->setText( strSN );

        mECC_PubXText->setPlainText( sECKey.pPubX );
        mECC_PubYText->setPlainText( sECKey.pPubY );
        mECC_PrivateText->setPlainText( sECKey.pPrivate );
    }

    JS_PKI_resetECKeyVal( &sECKey );
}

void PriKeyInfoDlg::setDSAKey( const BIN *pKey, bool bPri )
{
    int ret = 0;
    JDSAKeyVal sDSAKey;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    memset( &sDSAKey, 0x00, sizeof(sDSAKey));

    if( bPri == true )
        ret = JS_PKI_getDSAKeyVal( pKey, &sDSAKey );
    else
        ret = JS_PKI_getDSAKeyValFromPub( pKey, &sDSAKey );

    if( ret == 0 )
    {
        mDSA_GText->setPlainText( sDSAKey.pG );
        mDSA_PText->setPlainText( sDSAKey.pP );
        mDSA_QText->setText( sDSAKey.pQ );
        mDSA_PublicText->setPlainText( sDSAKey.pPublic );
        mDSA_PrivateText->setText( sDSAKey.pPrivate );
    }

    JS_PKI_resetDSAKeyVal( &sDSAKey );
}

void PriKeyInfoDlg::setEdDSAKey( const QString& strParam, const BIN *pKey, bool bPri )
{
    int ret = 0;
    int nType = 0;
    JRawKeyVal sRawKeyVal;

    if( pKey == NULL || pKey->nLen <= 0 ) return;

    if( strParam == kParamEd25519 )
        nType = JS_EDDSA_PARAM_25519;
    else
        nType = JS_EDDSA_PARAM_448;

    memset( &sRawKeyVal, 0x00, sizeof(sRawKeyVal));

    if( bPri == true )
        ret = JS_PKI_getRawKeyVal( pKey, &sRawKeyVal );
    else
        ret = JS_PKI_getRawKeyValFromPub( pKey, &sRawKeyVal );

    if( ret == 0 )
    {
        mEdDSA_NameText->setText( sRawKeyVal.pAlg );
        mEdDSA_RawPublicText->setPlainText( sRawKeyVal.pPub );
        mEdDSA_RawPrivateText->setPlainText( sRawKeyVal.pPri );
    }

    JS_PKI_resetRawKeyVal( &sRawKeyVal );
}

void PriKeyInfoDlg::setRSAKey( CK_OBJECT_HANDLE hKey, bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};
    JP11_CTX *pCTX = (JP11_CTX *)manApplet->P11CTX();

    ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_PUBLIC_EXPONENT, &binVal );
    if( ret == CKR_OK )
    {
        mRSA_EText->setText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        mRSA_EText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_MODULUS, &binVal );
    if( ret == CKR_OK )
    {
        mRSA_NText->setPlainText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        mRSA_NText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    if( bPri == true )
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_PRIVATE_EXPONENT, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_DText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mRSA_DText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_PRIME_1, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_PText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mRSA_PText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_PRIME_2, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_QText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mRSA_QText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_EXPONENT_1, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_DMP1Text->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mRSA_DMP1Text->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_EXPONENT_2, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_DMQ1Text->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mRSA_DMQ1Text->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }

        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_COEFFICIENT, &binVal );
        if( ret == CKR_OK )
        {
            mRSA_IQMPText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mRSA_IQMPText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::setECCKey( CK_OBJECT_HANDLE hKey, bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};

    JP11_CTX *pCTX = (JP11_CTX *)manApplet->P11CTX();

    char sTextOID[1024];

    JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_EC_PARAMS, &binVal );
    if( ret == CKR_OK )
    {
        JS_PKI_getStringFromOID( &binVal, sTextOID );
        JS_BIN_reset( &binVal );

        QString strSN = JS_PKI_getSNFromOID( sTextOID );

        mECC_CurveOIDText->setText( sTextOID );
        mECC_CurveSNText->setText( strSN );
    }
    else
    {
        mECC_CurveOIDText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    if( bPri == false )
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_EC_POINT, &binVal );
        if( ret == CKR_OK )
        {
            int nPubLen = (binVal.nLen - 3) / 2;
            mECC_PubXText->setPlainText( getHexString( &binVal.pVal[3], nPubLen));
            mECC_PubYText->setPlainText( getHexString( &binVal.pVal[3 + nPubLen], nPubLen));

            JS_BIN_reset( &binVal );
        }
        else
        {
            mECC_PubXText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
            mECC_PubYText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }
    else
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            mECC_PrivateText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mECC_PrivateText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::setDSAKey( CK_OBJECT_HANDLE hKey, bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};

    JP11_CTX *pCTX = (JP11_CTX *)manApplet->P11CTX();

    ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_PRIME, &binVal );
    if( ret == CKR_OK )
    {
        mDSA_PText->setPlainText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        mDSA_PText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_SUBPRIME, &binVal );
    if( ret == CKR_OK )
    {
        mDSA_QText->setText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        mDSA_QText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_BASE, &binVal );
    if( ret == CKR_OK )
    {
        mDSA_GText->setPlainText( getHexString( &binVal ) );
        JS_BIN_reset( &binVal );
    }
    else
    {
        mDSA_GText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
    }

    if( bPri == true )
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            mDSA_PrivateText->setText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mDSA_PrivateText->setText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }
    else
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            mDSA_PublicText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mDSA_PublicText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    JS_BIN_reset( &binVal );
}

void PriKeyInfoDlg::setEdDSAKey( CK_OBJECT_HANDLE hKey,  bool bPri )
{
    int ret = 0;
    BIN binVal = {0,0};
    QString strName;

    JP11_CTX *pCTX = (JP11_CTX *)manApplet->P11CTX();

    ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_EC_PARAMS, &binVal );
    if( ret == CKR_OK )
    {
        JS_BIN_reset( &binVal );
    }

    if( bPri == false )
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_EC_POINT, &binVal );
        if( ret == CKR_OK )
        {
            if( binVal.pVal[1] == 32 )
                strName = kParamEd25519;
            else
                strName = kParamEd448;

            mEdDSA_RawPublicText->setPlainText( getHexString( &binVal.pVal[2], binVal.nLen - 2 ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mEdDSA_RawPublicText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }
    else
    {
        ret = JS_PKCS11_GetAttributeValue2( pCTX, hKey, CKA_VALUE, &binVal );
        if( ret == CKR_OK )
        {
            if( binVal.nLen == 32 )
                strName = "ED25519";
            else
                strName = "ED448";

            mEdDSA_RawPrivateText->setPlainText( getHexString( &binVal ) );
            JS_BIN_reset( &binVal );
        }
        else
        {
            mEdDSA_RawPrivateText->setPlainText( QString( "[0x%1] %2" ).arg( ret, 0, 16 ).arg( JS_PKCS11_GetErrorMsg( ret )));
        }
    }

    mEdDSA_NameText->setText( strName );
    JS_BIN_reset( &binVal );
}


void PriKeyInfoDlg::changeRSA_N()
{
    QString strN = mRSA_NText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strN );
    mRSA_NLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_E( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_ELenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_D()
{
    QString strD = mRSA_DText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strD );
    mRSA_DLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_P( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_PLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_QLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_DMP1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMP1LenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_DMQ1( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_DMQ1LenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeRSA_IQMP( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mRSA_IQMPLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_PubX()
{
    QString strPubX = mECC_PubXText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubX );
    mECC_PubXLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_PubY()
{
    QString strPubY = mECC_PubYText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPubY );
    mECC_PubYLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeECC_Private()
{
    QString strPrivate = mECC_PrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPrivate );
    mECC_PrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_G()
{
    QString strG = mDSA_GText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strG );
    mDSA_GLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_P()
{
    QString strP = mDSA_PText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strP );
    mDSA_PLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Q( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_QLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Public()
{
    QString strPublic = mDSA_PublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strPublic );
    mDSA_PublicLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeDSA_Private( const QString& text )
{
    QString strLen = getDataLenString( DATA_HEX, text );
    mDSA_PrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPublic()
{
    QString strRawPublic = mEdDSA_RawPublicText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPublic );
    mEdDSA_RawPublicLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::changeEdDSA_RawPrivate()
{
    QString strRawPrivte = mEdDSA_RawPrivateText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strRawPrivte );
    mEdDSA_RawPrivateLenText->setText( QString("%1").arg(strLen));
}

void PriKeyInfoDlg::clickClear()
{
    mRSA_DText->clear();
    mRSA_EText->clear();
    mRSA_NText->clear();
    mRSA_PText->clear();
    mRSA_QText->clear();
    mRSA_DMP1Text->clear();
    mRSA_DMQ1Text->clear();
    mRSA_IQMPText->clear();

    mECC_PubXText->clear();
    mECC_PubYText->clear();
    mECC_CurveOIDText->clear();
    mECC_CurveSNText->clear();
    mECC_PrivateText->clear();

    mDSA_GText->clear();
    mDSA_PText->clear();
    mDSA_QText->clear();
    mDSA_PublicText->clear();
    mDSA_PrivateText->clear();

    mEdDSA_NameText->clear();
    mEdDSA_RawPublicText->clear();
    mEdDSA_RawPrivateText->clear();
}

void PriKeyInfoDlg::clickGetPrivateKey()
{
    QString strAlg = key_rec_.getAlg();

    clickClear();

    if( isPKCS11Private( strAlg ) == true )
    {
        readPrivateKeyHSM();
    }
    else if( isInternalPrivate( strAlg ) == true )
    {
        readPrivateKey();
    }
}

int PriKeyInfoDlg::readPrivateKey()
{
    BIN binPri = {0,0};
    QString strAlg = key_rec_.getAlg();

    manApplet->getPriKey( key_rec_.getPrivateKey(), &binPri );

    if( strAlg == kMechRSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( &binPri );
    }
    else if( strAlg == kMechEC || strAlg == kMechSM2 )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);

        if( strAlg == kMechSM2 )
            mInsertToHSMBtn->hide();

        setECCKey( &binPri );
    }
    else if( strAlg == kMechDSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( &binPri );
    }
    else if( strAlg == kMechEdDSA )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( key_rec_.getParam(), &binPri );
    }
    else
    {
        manApplet->warningBox( tr("Private key algorithm(%1) not supported").arg( strAlg ), this);
    }

    JS_BIN_reset( &binPri );
    return 0;
}

int PriKeyInfoDlg::readPrivateKeyHSM()
{
    int ret = 0;
    QString strAlg = key_rec_.getAlg();

    CK_OBJECT_HANDLE hKey = 0;

    int nIndex = manApplet->settingsMgr()->slotIndex();
    QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

    BIN binID = {0,0};
    JP11_CTX *pCTX = (JP11_CTX *)manApplet->P11CTX();
    ret = getP11Session( pCTX, nIndex, strPIN );

    if( ret != 0 )
    {
        manApplet->warnLog( tr("failed to get PKCS11 Session: %1").arg(ret), this );
        return JSR_ERR;
    }

    mInsertToHSMBtn->setEnabled( false );
    mKeyPairCheckBtn->setEnabled( false );

    JS_BIN_decodeHex( key_rec_.getPrivateKey().toStdString().c_str(), &binID );
    hKey = getHandleHSM( pCTX, CKO_PRIVATE_KEY, &binID );
    if( hKey <= 0 )
    {
        manApplet->warnLog( tr("fail to get private key handle"), this );
        ret = JSR_ERR2;
        goto end;
    }

    if( strAlg == kMechPKCS11_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( hKey );
    }
    else if( strAlg == kMechPKCS11_EC )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);
        setECCKey( hKey );
    }
    else if( strAlg == kMechPKCS11_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( hKey );
    }
    else if( strAlg == kMechPKCS11_EdDSA )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( hKey );
    }
    else
    {
        manApplet->warningBox( tr("Private key algorithm(%1) not supported").arg( strAlg ), this);
        ret = JSR_ERR3;
        goto end;
    }

    ret = 0;

end :
    JS_PKCS11_CloseSession( pCTX );
    JS_BIN_reset( &binID );
    return ret;
}

void PriKeyInfoDlg::clickGetPublicKey()
{
    BIN binPub = {0,0};
    QString strAlg = key_rec_.getAlg();

    clickClear();

    JS_BIN_decodeHex( key_rec_.getPublicKey().toStdString().c_str(), &binPub );

    if( strAlg == kMechRSA || strAlg == kMechPKCS11_RSA )
    {
        mKeyTab->setCurrentIndex(0);
        mKeyTab->setTabEnabled(0, true);
        setRSAKey( &binPub, false );
    }
    else if( strAlg == kMechEC || strAlg == kMechPKCS11_EC || strAlg == kMechSM2 )
    {
        mKeyTab->setCurrentIndex(1);
        mKeyTab->setTabEnabled(1, true);

        if( strAlg == kMechSM2 )
            mInsertToHSMBtn->hide();

        setECCKey( &binPub, false );
    }
    else if( strAlg == kMechDSA || strAlg == kMechPKCS11_DSA )
    {
        mKeyTab->setCurrentIndex( 2 );
        mKeyTab->setTabEnabled(2, true);
        setDSAKey( &binPub, false );
    }
    else if( strAlg == kMechEdDSA || strAlg == kMechPKCS11_EdDSA )
    {
        mKeyTab->setCurrentIndex( 3 );
        mKeyTab->setTabEnabled(3, true);
        setEdDSAKey( key_rec_.getParam(), &binPub, false );
    }
    else
    {
        manApplet->warningBox( tr("Public key algorithm(%1) not supported").arg( strAlg ), this);
    }

    JS_BIN_reset( &binPub );
}

void PriKeyInfoDlg::clickInsertToHSM()
{
    int ret = 0;
    BIN binHash = {0,0};
    JRSAKeyVal  sRSAKey;
    JECKeyVal   sECKey;
    JDSAKeyVal  sDSAKey;
    JRawKeyVal  sRawKey;

    BIN binPri = {0,0};
    BIN binPub = {0,0};
    QString strAlg = key_rec_.getAlg();
    QString strName = key_rec_.getName();
    KeyPairRec addKey;

    if( manApplet->settingsMgr()->PKCS11Use() == false ) return;

    memset( &sRSAKey, 0x00, sizeof(sRSAKey));
    memset( &sECKey, 0x00, sizeof(sECKey));
    memset( &sDSAKey, 0x00, sizeof(sDSAKey));
    memset( &sRawKey, 0x00, sizeof(sRawKey));

    int nIndex = manApplet->settingsMgr()->slotIndex();
    QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

    JP11_CTX *pCTX = (JP11_CTX *)manApplet->P11CTX();

    ret = getP11Session( pCTX, nIndex, strPIN );

    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to get PKCS11 Session: %1" ).arg( ret ) );
        goto end;
    }

    manApplet->getPriKey( key_rec_.getPrivateKey(), &binPri );

    JS_BIN_decodeHex( key_rec_.getPublicKey().toStdString().c_str(), &binPub );
    JS_PKI_genHash( "SHA1", &binPub, &binHash );

    if( strAlg == "RSA" )
    {
        JS_PKI_getRSAKeyVal( &binPri, &sRSAKey );
        ret = createRSAPrivateKeyP11( pCTX, strName, &binHash, &sRSAKey );
        if( ret != 0 ) goto end;
        ret = createRSAPublicKeyP11( pCTX, strName, &binHash, &sRSAKey );
        if( ret != 0 ) goto end;

        addKey.setAlg( kMechPKCS11_RSA );
    }
    else if( strAlg == "EC" || strAlg == "SM2" )
    {
        JS_PKI_getECKeyVal( &binPri, &sECKey );
        ret = createECPrivateKeyP11( pCTX, strName, &binHash, &sECKey );
        if( ret != 0 ) goto end;
        ret = createECPublicKeyP11( pCTX, strName, &binHash, &sECKey );
        if( ret != 0 ) goto end;

        addKey.setAlg( kMechPKCS11_EC );
    }
    else if( strAlg == "DSA" )
    {
        JS_PKI_getDSAKeyVal( &binPri, &sDSAKey );
        ret = createDSAPrivateKeyP11( pCTX, strName, &binHash, &sDSAKey );
        if( ret != 0 ) goto end;
        ret = createDSAPublicKeyP11( pCTX, strName, &binHash, &sDSAKey );
        if( ret != 0 ) goto end;

        addKey.setAlg( kMechPKCS11_DSA );
    }
    else if( strAlg == "EdDSA" )
    {
        QString strED_Name = mEdDSA_NameText->text();

        addKey.setAlg( kMechPKCS11_EdDSA );
        JS_PKI_getRawKeyVal( &binPri, &sRawKey );

        ret = createEDPrivateKeyP11( pCTX, strName, &binHash, &sRawKey );
        if( ret != 0 ) goto end;
        ret = createEDPublicKeyP11( pCTX, strName, &binHash, &sRawKey );
        if( ret != 0 ) goto end;
    }
    else
    {
        manApplet->elog( QString( "Invalid Algorithm: %1").arg(strAlg));
        goto end;
    }

    if( ret == 0 )
    {
        QString strMsg = tr("Successfully added private key and public key to HSM");
        manApplet->messageBox( strMsg, this );
        manApplet->log( strMsg );

        addKey.setRegTime( time(NULL) );
        addKey.setName( key_rec_.getName() + "_ToHSM" );
        addKey.setPublicKey( getHexString( &binPub ));
        addKey.setParam( key_rec_.getParam() );
        addKey.setPrivateKey( getHexString( &binHash ));
        addKey.setStatus(0);

        manApplet->dbMgr()->addKeyPairRec( addKey );
        manApplet->mainWindow()->createRightKeyPairList();
    }
    else
    {
        QString strMsg = tr("Failed to add private key and public key to HSM [%1]").arg(ret);
        manApplet->warningBox( strMsg, this );
        manApplet->elog( strMsg );
    }

end :
    JS_PKCS11_Logout( pCTX );
    JS_PKCS11_CloseSession( pCTX );

    JS_BIN_reset( &binHash );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );

    JS_PKI_resetRSAKeyVal( &sRSAKey );
    JS_PKI_resetECKeyVal( &sECKey );
    JS_PKI_resetDSAKeyVal( &sDSAKey );
    JS_PKI_resetRawKeyVal( &sRawKey );
}

void PriKeyInfoDlg::clickKeyPairCheck()
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    manApplet->getPriKey( key_rec_.getPrivateKey(), &binPri );


    JS_BIN_decodeHex( key_rec_.getPublicKey().toStdString().c_str(), &binPub );

    ret = JS_PKI_IsValidKeyPair( &binPri, &binPub );

    if( ret == JSR_VALID )
        manApplet->messageBox( tr( "KeyPair is valid"), this );
    else
        manApplet->warningBox( tr( "KeyPair is invalid"), this );

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
}
