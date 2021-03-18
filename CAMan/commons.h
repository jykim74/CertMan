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
#define     JS_STATUS_STOP        1
#define     JS_STATUS_VALID       2

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


const QStringList kHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
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

enum { JS_FILE_TYPE_CERT, JS_FILE_TYPE_PRIKEY, JS_FILE_TYPE_TXT, JS_FILE_TYPE_BER, JS_FILE_TYPE_DB, JS_FILE_TYPE_DLL };

QString findFile( QWidget *parent, int nType, const QString strPath );

int transExtInfoFromDBRec( JExtensionInfo *pExtInfo, PolicyExtRec policyExtRec );
int transExtInfoToDBRec( JExtensionInfo *pExtInfo, PolicyExtRec& policyExtRec );
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
QString getRevokeReasonName( int nReason );

#endif // COMMONS_H
