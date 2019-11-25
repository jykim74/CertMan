#ifndef COMMONS_H
#define COMMONS_H

#include <QString>
#include <QStringList>

#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_x509.h"

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

int setExtInfo( JSExtensionInfo *pExtInfo, PolicyExtRec policyExtRec );
int getExtInfo( JSExtensionInfo *pExtInfo, PolicyExtRec& policyExtRec );

#endif // COMMONS_H
