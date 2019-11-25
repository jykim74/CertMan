#include <QString>
#include <QtCore>

#include "commons.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "js_util.h"


static int _setKeyUsage( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    int nKeyUsage = 0;

    QStringList usageList = strVal.split("#");

    for( int i=0; i < usageList.size(); i++ )
    {
        QString usage = usageList.at(i);

        if( usage == "digitalSignature" )
            nKeyUsage |= JS_PKI_KEYUSAGE_DIGITAL_SIGNATURE;
        else if( usage == "nonRepudiation" )
            nKeyUsage |= JS_PKI_KEYUSAGE_NON_REPUDIATION;
        else if( usage == "keyEncipherment" )
            nKeyUsage |= JS_PKI_KEYUSAGE_KEY_ENCIPHERMENT;
        else if( usage == "dataEncipherment" )
            nKeyUsage |= JS_PKI_KEYUSAGE_DATA_ENCIPHERMENT;
        else if( usage == "keyAgreement" )
            nKeyUsage |= JS_PKI_KEYUSAGE_KEY_AGREEMENT;
        else if( usage == "keyCertSign" )
            nKeyUsage |= JS_PKI_KEYUSAGE_CERT_SIGN;
        else if( usage == "cRLSign" )
            nKeyUsage |= JS_PKI_KEYUSAGE_CRL_SIGN;
        else if( usage == "encipherOnly" )
            nKeyUsage |= JS_PKI_KEYUSAGE_ENCIPHER_ONLY;
        else if( usage == "decipherOnly" )
            nKeyUsage |= JS_PKI_KEYUSAGE_DECIPHER_ONLY;
    }

    ret = JS_PKI_setKeyUsageValue( pBinExt, nKeyUsage );

    return ret;
}

static int _getKeyUsage( const BIN *pBinExt, QString& strVal )
{
    int     ret = 0;
    int     nKeyUsage = 0;

    ret = JS_PKI_getKeyUsageValue( pBinExt, &nKeyUsage );

    if( nKeyUsage & JS_PKI_KEYUSAGE_DIGITAL_SIGNATURE )
        strVal += "Digital Signature,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_NON_REPUDIATION )
        strVal += "NonRepudiation,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_ENCIPHERMENT )
        strVal += "KeyEncipherment,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_DATA_ENCIPHERMENT )
        strVal += "DataEncipherment,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_AGREEMENT )
        strVal += "KeyAgreement,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_CERT_SIGN )
        strVal += "keyCertSign,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_CRL_SIGN )
        strVal += "cRLSign,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_ENCIPHER_ONLY )
        strVal += "EncipherOnly,";

    if( nKeyUsage & JS_PKI_KEYUSAGE_DECIPHER_ONLY )
        strVal += "DecipherOnly,";

    return 0;
}

static int _setCRLNum( BIN *pBinExt, const QString strVal )
{
    int ret = 0;

    ret = JS_PKI_setCRLNumberValue( pBinExt, strVal.toStdString().c_str() );

    return ret;
}

static int _getCRLNum( const BIN *pBinExt, QString& strVal )
{
    int ret = 0;
    char    *pCRLNum = NULL;

    ret = JS_PKI_getCRLNumberValue( pBinExt, &pCRLNum );

    if( pCRLNum ) {
        strVal = pCRLNum;
        JS_free( pCRLNum );
    }

    return 0;
}

static int _setCertPolicy( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSExtPolicyList *pPolicyList = NULL;
    QStringList strList = strVal.split("%%");

    for( int i=0; i < strList.size(); i++ )
    {
        JSExtPolicy sPolicy;
        QString strPolicy = strList.at(i);

        QStringList infoList = strPolicy.split("#");
        QString strOID = "";
        QString strCPS = "";
        QString strUserNotice = "";

        memset( &sPolicy, 0x00, sizeof(sPolicy));

        for( int k=0; k < infoList.size(); k++ )
        {
            QString strPart = infoList.at(k);

            if( strPart.startsWith( "OID$") )
                strOID = strPart.mid( 4 );
            else if( strPart.startsWith( "CPS$" ) )
                strCPS = strPart.mid( 4 );
            else if( strPart.startsWith( "UserNotice$" ) )
                strUserNotice = strPart.mid( 11 );
        }

        JS_PKI_setExtPolicy( &sPolicy,
                             strOID.toStdString().c_str(),
                             strCPS.toStdString().c_str(),
                             strUserNotice.toStdString().c_str() );

        if( pPolicyList == NULL )
            JS_PKI_createExtPolicyList( &sPolicy, &pPolicyList );
        else
            JS_PKI_appendExtPolicyList( pPolicyList, &sPolicy );

        JS_PKI_resetExtPolicy( &sPolicy );
    }

    ret = JS_PKI_setCertificatePoliciesValue( pBinExt, pPolicyList );
    if( pPolicyList ) JS_PKI_resetExtPolicyList( &pPolicyList );

    return ret;
}

static int _getCertPolicy( const BIN *pBinExt, QString& strVal )
{
    int ret = 0;
    JSExtPolicyList *pPolicyList = NULL;
    JSExtPolicyList *pCurList = NULL;

    ret = JS_PKI_getCertificatePoliciesValue( pBinExt, &pPolicyList );

    pCurList = pPolicyList;

    while( pCurList )
    {
        strVal += QString("#CPS$%1#OID$%2#UserNotice$%3")
                .arg( pCurList->sPolicy.pCPS )
                .arg( pCurList->sPolicy.pOID )
                .arg( pCurList->sPolicy.pUserNotice );

        strVal += "%%";

        pCurList = pCurList->pNext;
    }

    if( pPolicyList ) JS_PKI_resetExtPolicyList( &pPolicyList );
    return 0;
}

static int _setSKI( BIN *pBinExt, const QString strVal )
{
    int ret = 0;

    ret = JS_PKI_setSubjectKeyIdentifierValue( pBinExt, strVal.toStdString().c_str() );

    return ret;
}

static int _getSKI( const BIN *pBinExt, QString& strVal )
{
    int ret = 0;
    char        *pSKI = NULL;

    ret = JS_PKI_getSubjectKeyIdentifierValue( pBinExt, &pSKI );

    if( pSKI )
    {
        strVal = pSKI;
        JS_free( pSKI );
    }

    return 0;
}

static int _setAKI( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    QString strAKI ="";
    QString strIssuer = "";
    QString strSerial = "";

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);

        if( strPart.startsWith( "KEYID$" ) )
            strAKI = strPart.mid(6);
        else if( strPart.startsWith( "ISSUER$" ) )
            strIssuer = strPart.mid(7);
        else if( strPart.startsWith( "SERIAL$" ) )
            strSerial = strPart.mid(7);
    }

    ret = JS_PKI_setAuthorityKeyIdentifierValue( pBinExt,
                                                 strAKI.toStdString().c_str(),
                                                 strIssuer.toStdString().c_str(),
                                                 strSerial.toStdString().c_str() );

    return ret;
}

static int _getAKI( const BIN *pBinExt, QString& strVal )
{
    int ret = 0;
    char    *pAKI = NULL;
    char    *pIssuer = NULL;
    char    *pSerial = NULL;

    ret = JS_PKI_getAuthorityKeyIdentifierValue( pBinExt, &pAKI, &pIssuer, &pSerial );

    strVal = QString( "KEYID$%1#ISSUER$%2#SERIAL$%3").arg( pAKI ).arg( pIssuer ).arg( pSerial );

    if( pAKI ) JS_free( pAKI );
    if( pIssuer ) JS_free( pIssuer );
    if( pSerial ) JS_free( pSerial );

    return 0;
}

static int _setEKU( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSStrList *pEKUList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        QString info = infoList.at(i);

        if( pEKUList == NULL )
            JS_UTIL_createStrList( info.toStdString().c_str(), &pEKUList );
        else
            JS_UTIL_appendStrList( pEKUList, info.toStdString().c_str() );
    }

    ret = JS_PKI_setExtendedKeyUsageValue( pBinExt, pEKUList );

    if( pEKUList ) JS_UTIL_resetStrList( &pEKUList );

    return ret;
}

static int _getEKU( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setCRLDP( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSNameValList   *pDPList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i = 0; i < infoList.size(); i++ )
    {
        JSNameVal sNameVal;
        QString info = infoList.at(i);
        QStringList typeData = info.split( "$" );
        QString strType = typeData.at(0);
        QString strData = typeData.at(1);

        memset( &sNameVal, 0x00, sizeof(sNameVal) );
        JS_UTIL_setNameVal( &sNameVal, strType.toStdString().c_str(), strData.toStdString().c_str() );

        if( pDPList == NULL )
            JS_UTIL_createNameValList( &sNameVal, &pDPList );
        else
            JS_UTIL_appendNameValList( pDPList, &sNameVal );

        JS_UTIL_resetNameVal( &sNameVal );
    }

    ret = JS_PKI_setCRLDPValue( pBinExt, pDPList );
    if( pDPList ) JS_UTIL_resetNameValList( &pDPList );

    return ret;
}

static int _getCRLDP( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setBC( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    int nType = -1;
    int nPathLen = -1;

    QStringList infoList = strVal.split("#");
    QString strType = infoList.at(0);

    if( strType == "CA" )
        nType = JS_PKI_BC_TYPE_CA;
    else
        nType = JS_PKI_BC_TYPE_USER;

    if( infoList.size() > 1 )
        nPathLen = infoList.at(1).toInt();

    ret = JS_PKI_setBCValue( pBinExt, nType, nPathLen );
    return ret;
}

static int _getBC( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setPC( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    int nREP = -1;
    int nIPM = -1;

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        QString info = infoList.at(i);
        QStringList nameVal = info.split("$");

        QString name = nameVal.at(0);
        QString val = nameVal.at(1);

        if( name == "REP" )
            nREP = val.toInt();
        else if( name == "IPM" )
            nIPM = val.toInt();
    }

    ret = JS_PKI_setPolicyConstValue( pBinExt, nREP, nIPM );
    return ret;
}

static int _getPC( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setAIA( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSExtAuthorityInfoAccessList *pAIAList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strType = "";
        QString strMethod = "";
        QString strName = "";

        JSExtAuthorityInfoAccess sAIA;

        QString info = infoList.at(i);
        QStringList subList = info.split("$");

        memset( &sAIA, 0x00, sizeof(sAIA));

        strMethod = subList.at(0);
        strType = subList.at(1);
        strName = subList.at(2);

        JS_PKI_setExtAuthorityInfoAccess( &sAIA,
                                          strMethod.toStdString().c_str(),
                                          strType.toInt(),
                                          strName.toStdString().c_str() );

        if( pAIAList == NULL )
            JS_PKI_createExtAuthorityInfoAccessList( &sAIA, &pAIAList );
        else
            JS_PKI_appendExtAuthorityInfoAccessList( pAIAList, &sAIA );

        JS_PKI_resetExtAuthorityInfoAccess( &sAIA );
    }

    ret = JS_PKI_setAuthorityInfoAccessValue( pBinExt, pAIAList );
    if( pAIAList ) JS_PKI_resetExtAuthorityInfoAccessList( &pAIAList );

    return ret;
}

static int _getAIA( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setIDP( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSNumValList   *pIDPList = NULL;
    QStringList infoList = strVal.split("#");

    for( int i = 0; i < infoList.size(); i++ )
    {
        JSNumVal sNumVal;

        QString info = infoList.at(i);
        QStringList typeVal = info.split("$");

        QString type = typeVal.at(0);
        QString val = typeVal.at(1);
        int nType = -1;

        memset( &sNumVal, 0x00, sizeof(sNumVal));

        if( type == "URI" )
            nType = JS_PKI_NAME_TYPE_URI;
        else
            continue;

        JS_UTIL_setNumVal( &sNumVal, nType, val.toStdString().c_str() );

        if( pIDPList == NULL )
            JS_UTIL_createNumValList( &sNumVal, &pIDPList );
        else
            JS_UTIL_appendNumValList( pIDPList, &sNumVal );

        JS_UTIL_resetNumVal( &sNumVal );
    }

    ret = JS_PKI_setIssuingDistPointValue( pBinExt, pIDPList );

    if( pIDPList ) JS_UTIL_resetNumValList( &pIDPList );

    return ret;
}

static int _getIDP( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setAltName( BIN *pBinExt, int nNid, const QString strVal )
{
    int ret = 0;
    JSNumValList    *pNameList = NULL;
    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        JSNumVal sNumVal;
        int nType = -1;

        QString info = infoList.at(i);
        QStringList typeVal = info.split( "$" );

        QString type = typeVal.at(0);
        QString val = typeVal.at(1);

        memset( &sNumVal, 0x00, sizeof(sNumVal) );

        if( type == "URI" )
            nType = JS_PKI_NAME_TYPE_URI;
        else if( type == "DNS" )
            nType = JS_PKI_NAME_TYPE_DNS;
        else if( type == "email" )
            nType = JS_PKI_NAME_TYPE_EMAIL;

        JS_UTIL_setNumVal( &sNumVal, nType, val.toStdString().c_str() );

        if( pNameList == NULL )
            JS_UTIL_createNumValList( &sNumVal, &pNameList );
        else
            JS_UTIL_appendNumValList( pNameList, &sNumVal );

        JS_UTIL_resetNumVal( &sNumVal );
    }

    ret = JS_PKI_setAlternativNameValue( pBinExt, nNid, pNameList );
    if( pNameList ) JS_UTIL_resetNumValList( &pNameList );

    return ret;
}

static int _getAltName( const BIN *pBinExt, int nNid, QString& strVal )
{
    return 0;
}

static int _setPM( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSExtPolicyMappingsList *pPMList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        JSExtPolicyMappings sPM;

        QString info = infoList.at(i);
        QStringList valList = info.split("$");
        QString strIDP = valList.at(0);
        QString strSDP = valList.at(1);

        memset( &sPM, 0x00, sizeof(sPM));
        JS_PKI_setExtPolicyMappings( &sPM, strIDP.toStdString().c_str(), strSDP.toStdString().c_str() );

        if( pPMList == NULL )
            JS_PKI_createExtPolicyMappingsList( &sPM, &pPMList );
        else
            JS_PKI_appendExtPolicyMappingsList( pPMList, &sPM );

        JS_PKI_resetExtPolicyMappings( &sPM );
    }

    ret = JS_PKI_setPolicyMappingsValue( pBinExt, pPMList );
    if( pPMList ) JS_PKI_resetExtPolicyMappingsList( &pPMList );

    return ret;
}

static int _getPM( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setNC( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JSExtNameConstsList *pNCList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        JSExtNameConsts sNC;

        int nMin = -1;
        int nMax = -1;
        int nType = -1;
        int nKind = -1;

        QString info = infoList.at(i);
        QStringList valList = info.split("$");

        QString strType = valList.at(0);
        QString strKind = valList.at(1);
        QString strData = valList.at(2);

        if( strType == "URI" )
            nType = JS_PKI_NAME_TYPE_URI;
        else if( strType == "DNS" )
            nType = JS_PKI_NAME_TYPE_DNS;
        else if( strType == "email" )
            nType = JS_PKI_NAME_TYPE_EMAIL;

        if( strKind == "permittedSubtrees" )
            nKind = JS_PKI_NAME_CONSTS_KIND_PST;
        else if( strKind == "excludedSubtrees" )
            nKind = JS_PKI_NAME_CONSTS_KIND_EST;

        if( valList.size() > 3 ) nMax = valList.at(3).toInt();

        if( valList.size() > 4) nMin = valList.at(4).toInt();

        JS_PKI_setExtNameConsts( &sNC, nMin, nMax, nType, nKind, strData.toStdString().c_str() );

        if( pNCList == NULL )
            JS_PKI_createExtNameConstsList( &sNC, &pNCList );
        else
            JS_PKI_appendExtNameConstsList( pNCList, &sNC );

        JS_PKI_resetExtNameConsts( &sNC );
    }

    ret = JS_PKI_setNameConstraintsValue( pBinExt, pNCList );
    if( pNCList ) JS_PKI_resetExtNameConstsList( &pNCList );

    return ret;
}

static int _getNC( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

static int _setCRLReason( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    int nReason = strVal.toInt();

    ret = JS_PKI_setCRLReasonValue( pBinExt, nReason );

    return ret;
}

static int _getCRLReason( const BIN *pBinExt, QString& strVal )
{
    return 0;
}

int setExtInfo( JSExtensionInfo *pExtInfo, PolicyExtRec policyExtRec )
{
    int ret = 0;
    BIN binExt = {0,0};
    char sOID[1024];
    char *pHexVal = NULL;

    bool bCrit = policyExtRec.isCritical();
    QString strSN = policyExtRec.getSN();
    QString strVal = policyExtRec.getValue();

    memset( sOID, 0x00, sizeof(sOID) );

    JS_PKI_getOIDFromSN( strSN.toStdString().c_str(), sOID );

    if( strSN == kExtNameKeyUsage )
    {
        ret = _setKeyUsage( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLNum )
    {
        ret = _setCRLNum( &binExt, strVal );
    }
    else if( strSN == kExtNamePolicy )
    {
        ret = _setCertPolicy( &binExt, strVal );
    }
    else if( strSN == kExtNameSKI )
    {
        ret = _setSKI( &binExt, strVal );
    }
    else if( strSN == kExtNameAKI )
    {
        ret = _setAKI( &binExt, strVal );
    }
    else if( strSN == kExtNameEKU )
    {
        ret = _setEKU( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLDP )
    {
        ret = _setCRLDP( &binExt, strVal );
    }
    else if( strSN == kExtNameBC )
    {
        ret = _setBC( &binExt, strVal );
    }
    else if( strSN == kExtNamePC )
    {
        ret = _setPC( &binExt, strVal );
    }
    else if( strSN == kExtNameAIA )
    {
        ret = _setAIA( &binExt, strVal );
    }
    else if( strSN == kExtNameIDP )
    {
        ret = _setIDP( &binExt, strVal );
    }
    else if( strSN == kExtNameSAN || strSN == kExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _setAltName( &binExt, nNid, strVal );
    }
    else if( strSN == kExtNamePM )
    {
        ret = _setPM( &binExt, strVal );
    }
    else if( strSN == kExtNameNC )
    {
        ret = _setNC( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLReason )
    {
        ret = _setCRLReason( &binExt, strVal );
    }
    else
    {
        return -1;
    }


    if( ret == 0 )
    {
        JS_BIN_encodeHex( &binExt, &pHexVal );
        JS_PKI_setExtensionInfo( pExtInfo, bCrit, sOID, pHexVal );
    }

    JS_BIN_reset( &binExt );
    if( pHexVal ) JS_free( pHexVal );

    return ret;
}

int getExtInfo( JSExtensionInfo *pExtInfo, PolicyExtRec& policyExtRec )
{
    int ret = 0;
    QString strVal = "";
    QString strSN = pExtInfo->pOID;
    BIN     binExt = {0,0};

    JS_BIN_decodeHex( pExtInfo->pValue, &binExt );

    if( strSN == kExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, strVal );
    }
    else if( strSN == kExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, strVal );
    }
    else if( strSN == kExtNameSKI )
    {
        ret = _getSKI( &binExt, strVal );
    }
    else if( strSN == kExtNameAKI )
    {
        ret = _getAKI( &binExt, strVal );
    }
    else if( strSN == kExtNameEKU )
    {
        ret = _getEKU( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, strVal );
    }
    else if( strSN == kExtNameBC )
    {
        ret = _getBC( &binExt, strVal );
    }
    else if( strSN == kExtNamePC )
    {
        ret = _getPC( &binExt, strVal );
    }
    else if( strSN == kExtNameAIA )
    {
        ret = _getAIA( &binExt, strVal );
    }
    else if( strSN == kExtNameIDP )
    {
        ret = _getIDP( &binExt, strVal );
    }
    else if( strSN == kExtNameSAN || strSN == kExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, strVal );
    }
    else if( strSN == kExtNamePM )
    {
        ret = _getPM( &binExt, strVal );
    }
    else if( strSN == kExtNameNC )
    {
        ret = _getNC( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, strVal );
    }
    else
    {
//        return -1;
        strVal = pExtInfo->pValue;
    }

    policyExtRec.setSN( strSN );
    policyExtRec.setCritical( pExtInfo->bCritical );
    policyExtRec.setValue( strVal );

    return 0;
}
