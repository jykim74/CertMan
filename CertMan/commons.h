/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef COMMONS_H
#define COMMONS_H

#include <QString>
#include <QStringList>
#include <QTableWidgetItem>

#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_raw.h"
#include "js_pki_x509.h"
#include "js_pkcs11.h"
#include "js_kms.h"
#include "settings_mgr.h"
#include "js_pqc.h"

enum {
    DATA_HEX,
    DATA_STRING,
    DATA_BASE64,
    DATA_BASE64URL,
    DATA_URL
};

const QString kDataHex = "Hex";
const QString kDataString = "String";
const QString kDataBase64 = "Base64";
const QString kDataURL = "URL";
const QString kDataBase64URL = "Base64URL";

const QStringList kDataTypeList = { kDataHex, kDataString, kDataBase64 };
const QStringList kDataTypeList2 = { kDataHex, kDataString, kDataBase64, kDataURL, kDataBase64URL };
const QStringList kDataBinTypeList = { kDataHex, kDataBase64 };

const QString kEnvMiscGroup = "Misc";
const QString kEnvTempGroup = "Temp";

static QString kSelectStyle =
    "QTableWidget::item:selected { "
    "background-color: #9370db; "
    "color: white; "
    "} ";

const QString kReadOnlyStyle = "background-color:#ddddff";
const QString kDisableStyle = "background-color:#cccccc";

#define VIEW_FILE           0x01000000
#define VIEW_TOOL           0x02000000
#define VIEW_DATA           0x03000000
#define VIEW_SERVER         0x04000000
#define VIEW_HELP           0x05000000

#define ACT_FILE_NEW                    VIEW_FILE | 0x00000001
#define ACT_FILE_OPEN                   VIEW_FILE | 0x00000002
#define ACT_FILE_REMOTE_DB              VIEW_FILE | 0x00000004
#define ACT_FILE_LOGOUT                 VIEW_FILE | 0x00000008
#define ACT_FILE_QUIT                   VIEW_FILE | 0x00000010

#define ACT_TOOL_NEW_KEY                VIEW_TOOL | 0x00000001
#define ACT_TOOL_MAKE_REQ               VIEW_TOOL | 0x00000002
#define ACT_TOOL_MAKE_CONFIG            VIEW_TOOL | 0x00000004
#define ACT_TOOL_REG_USER               VIEW_TOOL | 0x00000008
#define ACT_TOOL_REG_SIGNER             VIEW_TOOL | 0x00000010
#define ACT_TOOL_MAKE_CERT_PROFILE      VIEW_TOOL | 0x00000020
#define ACT_TOOL_MAKE_CRL_PROFILE       VIEW_TOOL | 0x00000040
#define ACT_TOOL_MAKE_CERT              VIEW_TOOL | 0x00000080
#define ACT_TOOL_MAKE_CRL               VIEW_TOOL | 0x00000100
#define ACT_TOOL_REVOKE_CERT            VIEW_TOOL | 0x00000200
#define ACT_TOOL_CA_MAN                 VIEW_TOOL | 0x00000400
#define ACT_TOOL_PROFILE_MAN            VIEW_TOOL | 0x00000800

#define ACT_DATA_IMPORT_DATA            VIEW_DATA | 0x00000001
#define ACT_DATA_GET_URI                VIEW_DATA | 0x00000002
#define ACT_DATA_PUBLISH_LDAP           VIEW_DATA | 0x00000004
#define ACT_DATA_SET_PASSWD             VIEW_DATA | 0x00000008
#define ACT_DATA_CHANGE_PASSWD          VIEW_DATA | 0x00000010
#define ACT_DATA_TSP_CLIENT             VIEW_DATA | 0x00000020

#define ACT_SERVER_OCSP                 VIEW_SERVER | 0x00000001
#define ACT_SERVER_TSP                  VIEW_SERVER | 0x00000002
#define ACT_SERVER_CMP                  VIEW_SERVER | 0x00000004
#define ACT_SERVER_REG                  VIEW_SERVER | 0x00000008
#define ACT_SERVER_CC                   VIEW_SERVER | 0x00000010
#define ACT_SERVER_KMS                  VIEW_SERVER | 0x00000020

#define ACT_HELP_SERVER_STATUS          VIEW_HELP | 0x00000001
#define ACT_HELP_SETTING                VIEW_HELP | 0x00000002
#define ACT_HELP_CLEAR_LOG              VIEW_HELP | 0x00000004
#define ACT_HELP_HALT_LOG               VIEW_HELP | 0x00000008
#define ACT_HELP_LCN_INFO               VIEW_HELP | 0x00000010
#define ACT_HELP_BUG_ISSUE              VIEW_HELP | 0x00000020
#define ACT_HELP_QNA                    VIEW_HELP | 0x00000040
#define ACT_HELP_ABOUT                  VIEW_HELP | 0x00000080

static const int kFileDefault = ACT_FILE_NEW | ACT_FILE_OPEN | ACT_FILE_REMOTE_DB | ACT_FILE_LOGOUT;

static const int kToolDefault = ACT_TOOL_NEW_KEY | ACT_TOOL_MAKE_REQ | ACT_TOOL_MAKE_CONFIG \
                                | ACT_TOOL_REG_USER | ACT_TOOL_REG_SIGNER | ACT_TOOL_MAKE_CERT_PROFILE \
                                | ACT_TOOL_MAKE_CRL_PROFILE | ACT_TOOL_MAKE_CERT | ACT_TOOL_MAKE_CRL \
                                | ACT_TOOL_REVOKE_CERT | ACT_TOOL_CA_MAN | ACT_TOOL_PROFILE_MAN;

static const int kDataDefault = ACT_DATA_IMPORT_DATA | ACT_DATA_GET_URI | ACT_DATA_PUBLISH_LDAP \
                                | ACT_DATA_SET_PASSWD | ACT_DATA_CHANGE_PASSWD;

static const int kServerDefault = 0;

static const int kHelpDefault = ACT_HELP_SERVER_STATUS | ACT_HELP_LCN_INFO | ACT_HELP_BUG_ISSUE | ACT_HELP_QNA \
                                | ACT_HELP_ABOUT;

const int   kListCount = 15;

const int kPeriodDay = 0;
const int kPeriodMonth = 1;
const int kPeriodYear = 2;

const QString kMechPKCS11_RSA = "PKCS11_RSA";
const QString kMechPKCS11_ECDSA = "PKCS11_ECDSA";
const QString kMechPKCS11_DSA = "PKCS11_DSA";
const QString kMechPKCS11_EDDSA = "PKCS11_EdDSA";
const QString kMechKMIP_RSA = "KMIP_RSA";
const QString kMechKMIP_ECDSA = "KMIP_ECDSA";


const QStringList kStatusList = { "Invalid", "Valid", "Stop" };

//PrintableString curve25519
static unsigned char kCurveNameX25519[] = { 0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39 };
static unsigned char kOID_X25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x6E };

//PrintableString cruve448
static unsigned char kCurveNameX448[] = { 0x13, 0x08, 0x63, 0x75, 0x72, 0x76, 0x65, 0x34, 0x34, 0x38 };
static unsigned char kOID_X448[] = { 0x06, 0x03, 0x2B, 0x65, 0x6F };


const QStringList kHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SM3" };
const QStringList kKeyUsageList = {
    "digitalSignature", "nonRepudiation", "keyEncipherment",
    "dataEncipherment", "keyAgreement", "keyCertSign",
    "cRLSign", "encipherOnly", "decipherOnly"
};


const QStringList kExtKeyUsageList = {
    "serverAuth", "clientAuth", "codeSigning",
    "emailProtection", "timeStamping", "OCSPSigning",
    "ipsecIKE", "msCodeInd", "msCodeCom",
    "msCTLSign", "msEFS"
};

const QStringList kCertVersionList = { "V1", "V2", "V3" };
const QStringList kTypeList = { "URI", "email", "DNS" };
const QStringList kNCTypeList = { "URI", "email", "DNS", "dirName" };
const QStringList kAIATargetList = { "OCSP", "caIssuer" };
const QStringList kNCSubList = { "permittedSubtrees", "excludedSubtrees" };
const QStringList kBCTypeList = { "CA", "End Entity" };

const QStringList kRevokeReasonList = {
    "unspecified", "keyCompromise", "CACompromise",
    "affiliationChanged", "superseded", "cessationOfOperation",
    "certificateHold", "removeFromCRL", "holdInstruction",
    "keyTime","CAKeyTime"
};

static const QString kCSR_DN = "#CSR_DN";

static QStringList kRSAOptionList = { "1024", "2048", "3072", "4096", "8192" };
static QStringList kECCOptionList = { "prime256v1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1"
};



static QStringList kEdDSAOptionList = { JS_EDDSA_PARAM_NAME_25519, JS_EDDSA_PARAM_NAME_448 };
static QStringList kDSAOptionList = { "1024", "2048", "3072" };
static QStringList kML_DSAOptionList = {
    JS_PQC_PARAM_ML_DSA_44_NAME, JS_PQC_PARAM_ML_DSA_65_NAME, JS_PQC_PARAM_ML_DSA_87_NAME
};

static QStringList kSLH_DSAOptionList = {
    JS_PQC_PARAM_SLH_DSA_SHA2_128S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_128F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_192S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_192F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_256S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHA2_256F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_128S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_128F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_192S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_192F_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_256S_NAME,
    JS_PQC_PARAM_SLH_DSA_SHAKE_256F_NAME,
};

const QString kTableStyle = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
const QString kToolBoxStyle = "QToolBox::tab {background-color: #a8d5a2; }";

static QStringList kPBEv1List = { "PBE-SHA1-3DES", "PBE-SHA1-2DES" };
static QStringList kPBEv2List = { "AES-128-CBC", "AES-256-CBC", "ARIA-128-CBC", "ARIA-256-CBC" };

enum {
    JS_FILE_TYPE_CERT,
    JS_FILE_TYPE_CRL,
    JS_FILE_TYPE_CSR,
    JS_FILE_TYPE_PRIKEY,
    JS_FILE_TYPE_DB,
    JS_FILE_TYPE_DLL,
    JS_FILE_TYPE_TXT,
    JS_FILE_TYPE_BER,
    JS_FILE_TYPE_CFG,
    JS_FILE_TYPE_PFX,
    JS_FILE_TYPE_BIN,
    JS_FILE_TYPE_LCN,
    JS_FILE_TYPE_JSON,
    JS_FILE_TYPE_PKCS8,
    JS_FILE_TYPE_PKCS7,
    JS_FILE_TYPE_PRIKEY_PKCS8_PFX,
    JS_FILE_TYPE_ALL };

static QStringList kRemoteDBList = { "MySQL/MariaDB", "PostgreSQL", "Open DB Connectivity(ODBC)" };

const QString GetSystemID();



int transExtInfoFromDBRec( JExtensionInfo *pExtInfo, ProfileExtRec profileExtRec );
int transExtInfoToDBRec( const JExtensionInfo *pExtInfo, ProfileExtRec& profileExtRec );

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal );
const QString getExtValue( const QString strName, const QString strHexValue, bool bShow = true );

const QString getProfileExtInfoValue( const QString strSN, const QString& strVal );

int getP11Session( void *pP11CTX, int nSlotID, const QString strPIN = nullptr );
CK_OBJECT_HANDLE getHandleHSM( JP11_CTX *pCTX, CK_OBJECT_CLASS objClass, const BIN *pID );

int getKMIPConnection( SettingsMgr *settingMgr, SSL_CTX **ppCTX, SSL **ppSSL, Authentication **ppAuth );

int addAudit( DBMgr *dbMgr, int nKind, int nOP, QString strInfo );
int verifyAuditRec( AuditRec audit );

int writeCertDB( DBMgr *dbMgr, const BIN *pCert );
int writeCRLDB( DBMgr *dbMgr, const BIN *pCRL );
int writeCSRDB( DBMgr *dbMgr, int nKeyNum, const char *pName, const char *pDN, const char *pHash, const BIN *pCSR );


QString findPath(int bPri, QWidget *parent );
void CMPSetTrustList( SettingsMgr *settingMgr, BINList **ppTrustList );
QString getDateTime( time_t tTime );
QString getRecStatusName( int nStatus );
QString getAdminTypeName( int nType );
QString getStatusName( int nStatus );
QString getUserStatusName( int nStatus );
QString getSignerTypeName( int nType );
QString getCertStatusName( int nStatus );
QString getCertStatusSName( int nStatus );
QString getRevokeReasonName( int nReason );

int genKeyPairWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub );
int genKeyPairWithKMIP( SettingsMgr* settingMgr, QString strAlg, QString strParam, BIN *pPri, BIN *pPub);

int createRSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal );
int createRSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal );
int createECPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pEcKeyVal );
int createECPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pECKeyVal );
int createEDPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal );
int createEDPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal );
int createDSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );
int createDSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );

QString getHexString( const BIN *pBin );
QString getHexString( unsigned char *pData, int nDataLen );

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth = -1 );
const QString getHexStringArea( const BIN *pData, int nWidth = -1 );
const QString getHexStringArea( const QString strMsg, int nWidth = -1);

int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );
const QString getDataLenString( int nType, const QString strData );
const QString getDataLenString( const QString strType, const QString strData );

void getBINFromString( BIN *pBin, const QString& strType, const QString& strString );
void getBINFromString( BIN *pBin, int nType, const QString& strString );
QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly = false );
QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly = false );

const QString getPasswdHMAC( const QString &strPasswd );
const QString getNameFromDN( const QString& strDN );
const QString getExtensionUsageName( int nExtUsage );

int getKeyType( const QString& strAlg, const QString& strParam );
const QString getProfileType( int nProfileType );
const QString getExtUsage( int nExtUsage );
const QString getCRLDPFromInfo( const QString &strExtCRLDP );

bool isInternalPrivate( const QString strKeyMech );
bool isPKCS11Private( const QString strKeyMech );
bool isKMIPPrivate( const QString strKeyMech );
int getKeyMechType( const QString strKeyMech );

bool isValidNumFormat( const QString strInput, int nNumber );

bool isEmail( const QString strEmail );
bool isDNS( const QString strDNS );
bool isURL( const QString strURL );

bool isHex( const QString strHexString );
bool isBase64( const QString strBase64String );
bool isURLEncode( const QString strURLEncode );

const QString dateString( time_t tTime );
void getPeriodString( time_t start, time_t end, QString& strStart, QString& strEnd );

const QString getValueFromExtList( const QString strExtName, JExtensionInfoList *pExtList );
const QString getParamLabel( const QString strAlg );

int writePriKeyPEM( const BIN *pPriKey, const QString strPath );
int writePubKeyPEM( const BIN *pPubKey, const QString strPath );

void setFixedLineText( QLineEdit *pEdit, const QString strText );
#endif // COMMONS_H
