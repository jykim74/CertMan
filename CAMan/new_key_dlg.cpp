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
#include "js_kms.h"
#include "js_gen.h"
#include "commons.h"

static QStringList sMechList = { kMechRSA, kMechEC };

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
    mOptionCombo->setCurrentIndex(1);

    if( manApplet->settingsMgr()->PKCS11Use() )
    {
        mMechCombo->addItem( kMechPKCS11_RSA );
        mMechCombo->addItem( kMechPKCS11_EC );
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

    char *pPriHex = NULL;
    char *pPubHex = NULL;

    if( mMechCombo->currentIndex() == 0 )
    {
        int nKeySize = mOptionCombo->currentText().toInt();
        int nExponent = mExponentText->text().toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
    }
    else if( mMechCombo->currentIndex() == 1 )
    {
        int nGroupID = JS_PKI_getNidFromSN( mOptionCombo->currentText().toStdString().c_str() );
        ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPri );
    }
    else if( mMechCombo->currentIndex() == 2 || mMechCombo->currentIndex() == 3 )
    {
        QString strPin;
        PinDlg  pinDlg;
        int ret = pinDlg.exec();

        if( ret == QDialog::Accepted )
        {
            strPin = pinDlg.getPinText();
            ret = genKeyPairWithP11( strPin, &binPri, &binPub );
        }
        else
        {
            ret = -1;
        }
    }
    else if( mMechCombo->currentIndex() == 4 || mMechCombo->currentIndex() == 5 )
    {
        ret = genKeyPairWithKMIP( &binPri, &binPub );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to generate key pairs"), this );
        goto end;
    }

    JS_BIN_encodeHex( &binPri, &pPriHex );
    JS_BIN_encodeHex( &binPub, &pPubHex );

    keyPairRec.setAlg( mMechCombo->currentText() );
    keyPairRec.setRegTime( time(NULL) );
    keyPairRec.setName( strName );
    keyPairRec.setParam( mOptionCombo->currentText() );
    keyPairRec.setPublicKey( pPubHex );
    keyPairRec.setPrivateKey( pPriHex );
    keyPairRec.setStatus(0);

    dbMgr->addKeyPairRec( keyPairRec );
    addAudit( dbMgr, JS_GEN_KIND_CAMAN, JS_GEN_OP_GEN_KEY_PAIR, "" );

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

    if( index == 0 || index == 2 || index == 4 )
    {
        mOptionCombo->addItems(kRSAOptionList);
        mExponentLabel->setEnabled(true);
        mExponentText->setEnabled(true);
        mOptionLabel->setText( "Key size");
    }
    else if( index == 1 || index == 3 || index == 5 )
    {
        mOptionCombo->addItems(kECCOptionList);
        mExponentLabel->setEnabled(false);
        mExponentText->setEnabled(false);
        mOptionLabel->setText("NamedCurve");
    }
}

int NewKeyDlg::genKeyPairWithP11( QString strPin, BIN *pPri, BIN *pPub )
{
    JP11_CTX   *pP11CTX = NULL;

    int rv;

    pP11CTX = (JP11_CTX *)manApplet->P11CTX();
    int nSlotID = manApplet->settingsMgr()->slotID();

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    CK_LONG nFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

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

    rv = JS_PKCS11_OpenSession( pP11CTX, sSlotList[nSlotID], nFlags );
    if( rv != 0 ) goto end;


    rv = JS_PKCS11_Login( pP11CTX, nType, (CK_UTF8CHAR *)strPin.toStdString().c_str(), strPin.length() );
    if( rv != 0 ) goto end;

    rv = JS_PKCS11_GenerateKeyPair( pP11CTX, &sMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubObj, &uPriObj );
    if( rv != 0 ) goto end;

    if( keyType == CKK_RSA )
    {
        char *pN = NULL;
        char *pE = NULL;

        rv = JS_PKCS11_GetAtrributeValue2( pP11CTX, uPubObj, CKA_MODULUS, &binVal );
        if( rv != 0 ) goto end;

        JRSAKeyVal  rsaKey;
        memset( &rsaKey, 0x00, sizeof(rsaKey));

        JS_BIN_encodeHex( &binVal, &pN );
        JS_BIN_encodeHex( &binPubExponent, &pE );

        JS_PKI_setRSAKeyVal( &rsaKey, pN, pE, NULL, NULL, NULL, NULL, NULL, NULL );
        JS_PKI_encodeRSAPublicKey( &rsaKey, pPub );

        if( pN ) JS_free( pN );
        if( pE ) JS_free( pE );
        JS_PKI_resetRSAKeyVal( &rsaKey );
    }
    else if( keyType == CKK_ECDSA )
    {
        rv = JS_PKCS11_GetAtrributeValue2( pP11CTX, uPubObj, CKA_EC_POINT, &binVal );
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
        JS_PKI_encodeECPublicKey( &ecKey, pPub );

        if( pECPoint ) JS_free( pECPoint );
        if( pGroup ) JS_free( pGroup );
        JS_BIN_reset( &binKey );
        JS_PKI_resetECKeyVal( &ecKey );
    }

    JS_PKI_genHash( "SHA1", pPub, &binHash );
    JS_BIN_copy( pPri, &binHash );

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uPriObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uPubObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

end :
    if( pP11CTX->hSession >= 0 )
    {
        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
    }

    return rv;
}

int NewKeyDlg::genKeyPairWithKMIP( BIN *pPri, BIN *pPub )
{
    int ret = 0;
    Authentication *pAuth = NULL;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;
    BIN binData = {0,0};


    int nAlg = JS_PKI_KEY_TYPE_RSA;
    int nParam = mOptionCombo->currentText().toInt();
    int nType = -1;

    if( mMechCombo->currentText() == kMechKMIP_RSA )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
        nParam = mOptionCombo->currentText().toInt();
    }
    else if( mMechCombo->currentText() == kMechKMIP_EC )
    {
        nAlg = JS_PKI_KEY_TYPE_ECC;
        nParam = KMIP_CURVE_P_256;
    }
    else
    {
        fprintf( stderr, "Invalid mechanism\n" );
        return -1;
    }

    char *pPriUUID = NULL;
    char *pPubUUID = NULL;

    ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    ret = JS_KMS_encodeCreateKeyPairReq( pAuth, nAlg, nParam, &binReq );
    ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    ret = JS_KMS_decodeCreateKeyPairRsp( &binRsp, &pPubUUID, &pPriUUID );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_SSL_clear( pSSL );
    pSSL = NULL;

    ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    ret = JS_KMS_encodeGetReq( pAuth, pPubUUID, &binReq );
    ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    ret = JS_KMS_decodeGetRsp( &binRsp, &nType, &binData );

    if( nAlg == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAKey;
        char *pN = NULL;
        char *pE = NULL;

        memset( &sRSAKey, 0x00, sizeof(sRSAKey));
        JS_PKI_getRSAPublicKeyVal( &binData, &pE, &pN );
        JS_PKI_setRSAKeyVal( &sRSAKey, pN, pE, NULL, NULL, NULL, NULL, NULL, NULL );
        JS_PKI_encodeRSAPublicKey( &sRSAKey, pPub );

        if( pN ) JS_free( pN );
        if( pE ) JS_free( pE );
        JS_PKI_resetRSAKeyVal( &sRSAKey );
    }
    else if( nAlg == JS_PKI_KEY_TYPE_ECC )
    {
        BIN binGroup = {0,0};
        char *pECPoint = NULL;
        char *pGroup = NULL;

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        char    sHexOID[128];
        memset( sHexOID, 0x00, sizeof(sHexOID));

        JS_PKI_getHexOIDFromSN( "prime256v1", sHexOID );
        JS_BIN_decodeHex( sHexOID, &binGroup );

        BIN binKey = {0,0};
        JS_BIN_set( &binKey, binData.pVal + 2, binData.nLen - 2 );

        JS_BIN_encodeHex( &binKey, &pECPoint );
        JS_BIN_encodeHex( &binGroup, &pGroup );

        JS_PKI_setECKeyVal( &ecKey, pGroup, pECPoint, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub );

        if( pECPoint ) JS_free( pECPoint );
        if( pGroup ) JS_free( pGroup );
        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binGroup );
        JS_PKI_resetECKeyVal( &ecKey );
    }

    JS_BIN_set( pPri, (unsigned char *)pPriUUID, strlen( pPriUUID ) );

 end :
    if( pPubUUID ) JS_free( pPubUUID );
    if( pPriUUID ) JS_free( pPriUUID );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth )
    {
        JS_KMS_resetAuthentication( pAuth );
        JS_free( pAuth );
    }

    return ret;
}
