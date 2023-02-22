#ifndef COMMONS_H
#define COMMONS_H

#include <QString>
#include <QStringList>

#include "db_mgr.h"
#include "js_pki.h"
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

const int   kListCount = 15;

const QString kMechRSA = "RSA";
const QString kMechEC = "EC";
const QString kMechPKCS11_RSA = "PKCS11_RSA";
const QString kMechPKCS11_EC = "PKCS11_EC";
const QString kMechKMIP_RSA = "KMIP_RSA";
const QString kMechKMIP_EC = "KMIP_EC";

const QString kExtNameAIA = "authorityInfoAccess";
const QString kExtNameAKI = "authorityKeyIdentifier";
const QString kExtNameBC = "basicConstraints";
const QString kExtNameCRLDP = "crlDistributionPoints";
const QString kExtNameEKU = "extendedKeyUsage";
const QString kExtNameIAN = "issuerAltName";
const QString kExtNameKeyUsage = "keyUsage";
const QString kExtNameNC = "nameConstraints";
const QString kExtNamePolicy = "certificatePolicies";
const QString kExtNamePC = "policyConstraints";
const QString kExtNamePM = "policyMappings";
const QString kExtNameSKI = "subjectKeyIdentifier";
const QString kExtNameSAN = "subjectAltName";
const QString kExtNameCRLNum = "crlNumber";
const QString kExtNameIDP = "issuingDistributionPoint";
const QString kExtNameCRLReason = "CRLReason";

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
const QStringList kAIATargetList = { "OCSP", "caIssuer" };
const QStringList kNCSubList = { "permittedSubtrees", "excludedSubtrees" };
const QStringList kBCTypeList = { "CA", "End Entity" };

const QStringList kRevokeReasonList = {
    "unspecified", "keyCompromise", "CACompromise",
    "affiliationChanged", "superseded", "cessationOfOperation",
    "certificateHold", "removeFromCRL", "holdInstruction",
    "keyTime","CAKeyTime"
};

static QStringList kRSAOptionList = { "1024", "2048", "3072", "4096" };
static QStringList kECCOptionList = {
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192r1", "secp192k1", "secp224k1",
    "secp224r1", "prime256v1", "secp256k1", "secp384r1", "secp521r1",
    "sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1",
    "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
    "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1",
    "sect409r1", "sect571k1", "sect571r1", "SM2"
};


const QString kTableStyle = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

enum { JS_FILE_TYPE_CERT, JS_FILE_TYPE_PRIKEY, JS_FILE_TYPE_TXT, JS_FILE_TYPE_BER, JS_FILE_TYPE_DB, JS_FILE_TYPE_DLL };

QString findFile( QWidget *parent, int nType, const QString strPath );

int transExtInfoFromDBRec( JExtensionInfo *pExtInfo, ProfileExtRec profileExtRec );
int transExtInfoToDBRec( const JExtensionInfo *pExtInfo, ProfileExtRec& profileExtRec );

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal );

CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotID );

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

int genKeyPairWithP11( JP11_CTX *pCTX, int nSlotID, QString strPin, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub );
int genKeyPairWithKMIP( SettingsMgr* settingMgr, QString strAlg, QString strParam, BIN *pPri, BIN *pPub);
QString getHexString( const BIN *pBin );

#endif // COMMONS_H
