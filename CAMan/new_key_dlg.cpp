#include "new_key_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_bin.h"
#include "db_mgr.h"
#include "key_pair_rec.h"
#include "settings_mgr.h"
#include "pin_dlg.h"
#include "js_pkcs11.h"

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
    mOptionCombo->addItems(sRSAOptionList);

    if( manApplet->settingsMgr()->PKCS11Use() )
    {
        mMechCombo->addItem( "PKCS11_RSA" );
        mMechCombo->addItem( "PKCS11_ECC" );
    }

    mExponentText->setText( QString( "65537" ) );
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
    else if( mMechCombo->currentIndex() == 2 || mMechCombo->currentIndex() == 3 )
    {
        QString strPin;
        PinDlg  pinDlg;
        int ret = pinDlg.exec();

        if( ret == QDialog::Accepted )
        {
            strPin = pinDlg.getPinText();
            ret = genKeyPairWithP11( strPin, &binPri, &binPub, &binPub2 );
        }
        else
        {
            ret = -1;
        }
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


    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightKeyPairList();
        QDialog::accept();
    }
}

void NewKeyDlg::mechChanged(int index )
{
    mOptionCombo->clear();

    if( index == 0 || index == 2 )
    {
        mOptionCombo->addItems(sRSAOptionList);
        mExponentText->setEnabled(true);
        mOptionLabel->setText( "Key size");
    }
    else if( index == 1 || index == 3 )
    {
        mOptionCombo->addItems(sECCOptionList);
        mExponentText->setEnabled(false);
        mOptionLabel->setText("NamedCurve");
    }
}

int NewKeyDlg::genKeyPairWithP11( QString strPin, BIN *pPri, BIN *pPub, BIN *pPub2 )
{
    JP11_CTX   *pP11CTX = NULL;

    int rv;

    pP11CTX = (JP11_CTX *)manApplet->P11CTX();
    int nSlotID = manApplet->settingsMgr()->slotID();

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    CK_LONG nFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SESSION_HANDLE uSession = -1;
    CK_USER_TYPE nType = CKU_USER;

    CK_ATTRIBUTE sPubTemplate[20];
    CK_ULONG uPubCount = 0;
    CK_ATTRIBUTE sPriTemplate[20];
    CK_ULONG uPriCount = 0;
    CK_MECHANISM sMech;
    CK_ULONG modulusBits = 0;
    CK_KEY_TYPE keyType;

    CK_OBJECT_HANDLE uPubObj = 0;
    CK_OBJECT_HANDLE uPriObj = 0;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;

    QString strName = mNameText->text();
    BIN binLabel = {0,0};
    JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.length() );


    BIN binPubExponent = {0,0};
    BIN binGroup = {0,0};
    CK_ULONG	uModBitLen = 0;

    BIN binVal = {0,0};
    BIN binHash = {0,0};

    memset( &sMech, 0x00, sizeof(sMech) );

    int iSelMech = mMechCombo->currentIndex();

    if( iSelMech == 2 )
    {
        sMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        keyType = CKK_RSA;
    }
    else if( iSelMech == 3 )
    {
        sMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
        keyType = CKK_ECDSA;
    }

    sPubTemplate[uPubCount].type = CKA_CLASS;
    sPubTemplate[uPubCount].pValue = &pubClass;
    sPubTemplate[uPubCount].ulValueLen = sizeof( pubClass );
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_KEY_TYPE;
    sPubTemplate[uPubCount].pValue = &keyType;
    sPubTemplate[uPubCount].ulValueLen = sizeof( keyType );
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_LABEL;
    sPubTemplate[uPubCount].pValue = binLabel.pVal;
    sPubTemplate[uPubCount].ulValueLen = binLabel.nLen;
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_ID;
    sPubTemplate[uPubCount].pValue = binLabel.pVal;
    sPubTemplate[uPubCount].ulValueLen = binLabel.nLen;
    uPubCount++;

    if( keyType == CKK_RSA )
    {
        QString strDecimal = "";
        strDecimal.sprintf( "%d", mExponentText->text().toInt() );
        JS_PKI_decimalToBin( strDecimal.toStdString().c_str(), &binPubExponent );

        sPubTemplate[uPubCount].type = CKA_PUBLIC_EXPONENT;
        sPubTemplate[uPubCount].pValue = binPubExponent.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubExponent.nLen;
        uPubCount++;

        uModBitLen = mOptionCombo->currentText().toInt();

        sPubTemplate[uPubCount].type = CKA_MODULUS_BITS;
        sPubTemplate[uPubCount].pValue = &uModBitLen;
        sPubTemplate[uPubCount].ulValueLen = sizeof( uModBitLen );
        uPubCount++;
    }
    else if( keyType == CKK_ECDSA )
    {
        char    sHexOID[128];
        memset( sHexOID, 0x00, sizeof(sHexOID));

        JS_PKI_getHexOIDFromSN( mOptionCombo->currentText().toStdString().c_str(), sHexOID );

        QString strGroup;
        strGroup.sprintf( "06%02x%s", strlen(sHexOID) / 2, sHexOID );
        JS_BIN_decodeHex( sHexOID, &binGroup );

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binGroup.pVal;
        sPubTemplate[uPubCount].ulValueLen = binGroup.nLen;
        uPubCount++;
    }

    sPubTemplate[uPubCount].type = CKA_TOKEN;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_VERIFY;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    if( keyType == CKK_RSA )
    {
        sPubTemplate[uPubCount].type = CKA_ENCRYPT;
        sPubTemplate[uPubCount].pValue = &bTrue;
        sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_WRAP;
        sPubTemplate[uPubCount].pValue = &bTrue;
        sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
        uPubCount++;
    }

    /* Pri template */
    sPriTemplate[uPriCount].type = CKA_CLASS;
    sPriTemplate[uPriCount].pValue = &priClass;
    sPriTemplate[uPriCount].ulValueLen = sizeof( priClass );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_KEY_TYPE;
    sPriTemplate[uPriCount].pValue = &keyType;
    sPriTemplate[uPriCount].ulValueLen = sizeof( keyType );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_LABEL;
    sPriTemplate[uPriCount].pValue = binLabel.pVal;
    sPriTemplate[uPriCount].ulValueLen = binLabel.nLen;
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_ID;
    sPriTemplate[uPriCount].pValue = binLabel.pVal;
    sPriTemplate[uPriCount].ulValueLen = binLabel.nLen;
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_TOKEN;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_PRIVATE;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    if( keyType == CKK_RSA )
    {
        sPriTemplate[uPriCount].type = CKA_DECRYPT;
        sPriTemplate[uPriCount].pValue = &bTrue;
        sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
        uPriCount++;

        sPriTemplate[uPriCount].type = CKA_UNWRAP;
        sPriTemplate[uPriCount].pValue = &bTrue;
        sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
        uPriCount++;
    }

    sPriTemplate[uPriCount].type = CKA_SENSITIVE;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_SIGN;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof( bTrue );
    uPriCount++;

    rv = JS_PKCS11_GetSlotList2( pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( rv != 0 ) goto end;

    if( uSlotCnt < nSlotID )
        goto end;

    rv = JS_PKCS11_OpenSession( pP11CTX, sSlotList[nSlotID], nFlags, (CK_SESSION_HANDLE_PTR)&uSession );
    if( rv != 0 ) goto end;


    rv = JS_PKCS11_Login( pP11CTX, uSession, nType, (CK_UTF8CHAR *)strPin.toStdString().c_str(), strPin.length() );
    if( rv != 0 ) goto end;

    rv = JS_PKCS11_GenerateKeyPair( pP11CTX, uSession, &sMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubObj, &uPriObj );
    if( rv != 0 ) goto end;

    if( keyType == CKK_RSA )
    {
        char *pN = NULL;
        char *pE = NULL;

        rv = JS_PKCS11_GetAtrributeValue2( pP11CTX, uSession, uPubObj, CKA_MODULUS, &binVal );
        if( rv != 0 ) goto end;

        JRSAKeyVal  rsaKey;
        memset( &rsaKey, 0x00, sizeof(rsaKey));

        JS_BIN_encodeHex( &binVal, &pN );
        JS_BIN_encodeHex( &binPubExponent, &pE );

        JS_PKI_setRSAKeyVal( &rsaKey, pN, pE, NULL, NULL, NULL, NULL, NULL, NULL );
        JS_PKI_encodeRSAPublicKey( &rsaKey, pPub, pPub2 );

        if( pN ) JS_free( pN );
        if( pE ) JS_free( pE );
        JS_PKI_resetRSAKeyVal( &rsaKey );
    }
    else if( keyType == CKK_ECDSA )
    {
        rv = JS_PKCS11_GetAtrributeValue2( pP11CTX, uSession, uPubObj, CKA_EC_POINT, &binVal );
        if( rv != 0 ) goto end;

        char *pECPoint = NULL;
        char *pGroup = NULL;

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        BIN binKey = {0,0};
        JS_BIN_set( &binKey, binVal.pVal + 2, binVal.nLen - 2 );

        JS_BIN_encodeHex( &binKey, &pECPoint );
        JS_BIN_encodeHex( &binGroup, &pGroup );

        JS_PKI_setECKeyVal( &ecKey, pGroup, pECPoint, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub, pPub2 );

        if( pECPoint ) JS_free( pECPoint );
        if( pGroup ) JS_free( pGroup );
        JS_BIN_reset( &binKey );
        JS_PKI_resetECKeyVal( &ecKey );
    }

    JS_PKI_genHash( "SHA1", pPub, &binHash );
    JS_BIN_copy( pPri, &binHash );

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uSession, uPriObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uSession, uPubObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

end :
    if( uSession >= 0 )
    {
        JS_PKCS11_Logout( pP11CTX, uSession );
        JS_PKCS11_CloseSession( pP11CTX, uSession );
    }

    return rv;
}
