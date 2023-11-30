#ifndef COMMONS_H
#define COMMONS_H

#include <QString>
#include <QStringList>
#include <QTableWidgetItem>

#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_eddsa.h"
#include "js_pki_x509.h"
#include "js_pkcs11.h"
#include "js_kms.h"
#include "settings_mgr.h"

#define     JS_REC_STATUS_NOT_USED          0
#define     JS_REC_STATUS_USED              1

#define     JS_STATUS_INVALID     0
#define     JS_STATUS_VALID       1
#define     JS_STATUS_STOP        2

#define     JS_ADMIN_TYPE_INVALID       0
#define     JS_ADMIN_TYPE_MASTER        1
#define     JS_ADMIN_TYPE_ADMIN         2
#define     JS_ADMIN_TYPE_AUDIT         3

#define     JS_USER_STATUS_INVALID      0
#define     JS_USER_STATUS_REGISTER     1
#define     JS_USER_STATUS_ISSUED       2
#define     JS_USER_STATUS_STOP         3

#define     JS_SIGNER_TYPE_REG     0
#define     JS_SIGNER_TYPE_OCSP    1

#define     JS_CERT_STATUS_INVALID      0
#define     JS_CERT_STATUS_GOOD         1
#define     JS_CERT_STATUS_REVOKE       2
#define     JS_CERT_STATUS_HOLD         3

/*
#define     JS_NO_LICENSE_SELF_LIMIT_COUNT          1
#define     JS_NO_LICENSE_CA_LIMIT_COUNT            2
#define     JS_NO_LICENSE_KEYPAIR_LIMIT_COUNT       8
#define     JS_NO_LICENSE_CSR_LIMIT_COUNT           8
#define     JS_NO_LICENSE_CERT_LIMIT_COUNT          32
#define     JS_NO_LICENSE_CRL_LIMIT_COUNT           32
*/

enum {
    DATA_STRING,
    DATA_HEX,
    DATA_BASE64,
    DATA_URL
};

const int   kListCount = 15;

const QString kMechRSA = "RSA";
const QString kMechEC = "EC";
const QString kMechEdDSA = "EdDSA";
const QString kMechDSA = "DSA";
const QString kMechEd25519 = "Ed25519";
const QString kMechEd448 = "Ed448";
const QString kMechPKCS11_RSA = "PKCS11_RSA";
const QString kMechPKCS11_EC = "PKCS11_EC";
const QString kMechPKCS11_DSA = "PKCS11_DSA";
const QString kMechKMIP_RSA = "KMIP_RSA";
const QString kMechKMIP_EC = "KMIP_EC";

const QStringList kStatusList = { "Invalid", "Valid", "Stop" };


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

static QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
static QStringList kECCOptionList = { "prime256v1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1", "SM2"
};



static QStringList kEdDSAOptionList = { kMechEd25519, kMechEd448 };
static QStringList kDSAOptionList = { "1024", "2048", "3072", "4096" };

const QString kTableStyle = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

static QStringList kPBEv1List = { "PBE-SHA1-3DES", "PBE-SHA1-2DES" };
static QStringList kPBEv2List = { "AES-128-CBC", "AES-256-CBC", "ARIA-128-CBC", "ARIA-256-CBC" };

enum {
    JS_FILE_TYPE_CERT,
    JS_FILE_TYPE_PRIKEY,
    JS_FILE_TYPE_TXT,
    JS_FILE_TYPE_BER,
    JS_FILE_TYPE_DB,
    JS_FILE_TYPE_DLL,
    JS_FILE_TYPE_LCN };

static QStringList kRemoteDBList = { "MySQL/MariaDB", "PostgreSQL", "Open DB Connectivity(ODBC)" };

QString findFile( QWidget *parent, int nType, const QString strPath );

int transExtInfoFromDBRec( JExtensionInfo *pExtInfo, ProfileExtRec profileExtRec );
int transExtInfoToDBRec( const JExtensionInfo *pExtInfo, ProfileExtRec& profileExtRec );

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal );
const QString getProfileExtInfoValue( const QString strSN, const QString& strVal );

CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotID, const QString strPIN = nullptr );

int getKMIPConnection( SettingsMgr *settingMgr, SSL_CTX **ppCTX, SSL **ppSSL, Authentication **ppAuth );

int addAudit( DBMgr *dbMgr, int nKind, int nOP, QString strInfo );
int verifyAuditRec( AuditRec audit );

int writeCertDB( DBMgr *dbMgr, const BIN *pCert );
int writeCRLDB( DBMgr *dbMgr, const BIN *pCRL );
int writeCSRDB( DBMgr *dbMgr, int nKeyNum, const char *pName, const char *pDN, const char *pHash, const BIN *pCSR );
int writeKeyPairDB( DBMgr *dbMgr, const char *pName, const BIN *pPub, const BIN *pPri );


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
int createDSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );
int createDSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal );

QString getHexString( const BIN *pBin );

int getDataLen( int nType, const QString strData );
int getDataLen( const QString strType, const QString strData );

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

#endif // COMMONS_H
