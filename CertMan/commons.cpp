#include <QObject>
#include <QString>
#include <QtCore>
#include <QFileDialog>


#include "commons.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "pin_dlg.h"
#include "audit_rec.h"
#include "js_gen.h"


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

static int _getKeyUsage( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     nKeyUsage = 0;

    ret = JS_PKI_getKeyUsageValue( pBinExt, &nKeyUsage );

    if( nKeyUsage & JS_PKI_KEYUSAGE_DIGITAL_SIGNATURE )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DigitalSignature";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_NON_REPUDIATION )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "NonRepudiation";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_ENCIPHERMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "KeyEncipherment";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_DATA_ENCIPHERMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DataEncipherment";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_KEY_AGREEMENT )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "KeyAgreement";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_CERT_SIGN )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "keyCertSign";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_CRL_SIGN )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "cRLSign";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_ENCIPHER_ONLY )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "EncipherOnly";
    }

    if( nKeyUsage & JS_PKI_KEYUSAGE_DECIPHER_ONLY )
    {
        if( strVal.length() > 0 ) strVal += ",";
        strVal += "DecipherOnly";
    }

    return 0;
}

static int _setCRLNum( BIN *pBinExt, const QString strVal )
{
    int ret = 0;

    ret = JS_PKI_setCRLNumberValue( pBinExt, strVal.toStdString().c_str() );

    return ret;
}

static int _getCRLNum( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char    *pCRLNum = NULL;

    ret = JS_PKI_getCRLNumberValue( pBinExt, &pCRLNum );

    if( pCRLNum ) {
        if(bShow)
            strVal = QString( "CRL Number=%1" ).arg( pCRLNum );
        else
            strVal = pCRLNum;

        JS_free( pCRLNum );
    }

    return 0;
}

static int _setCertPolicy( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JExtPolicyList *pPolicyList = NULL;
    QStringList strList = strVal.split("%%");

    for( int i=0; i < strList.size(); i++ )
    {
        JExtPolicy sPolicy;
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
                             strOID.length() > 1 ? strOID.toStdString().c_str() : NULL,
                             strCPS.length() > 1 ? strCPS.toStdString().c_str() : NULL,
                             strUserNotice.length() > 1 ? strUserNotice.toStdString().c_str() : NULL );

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

static int _getCertPolicy( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 0;
    JExtPolicyList *pPolicyList = NULL;
    JExtPolicyList *pCurList = NULL;

    ret = JS_PKI_getCertificatePoliciesValue( pBinExt, &pPolicyList );

    pCurList = pPolicyList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1]Certificate Policy:\n" ).arg(i+1);
            strVal += QString( " Policy Identifier=%1\n" ).arg( pCurList->sPolicy.pOID );
            if( pCurList->sPolicy.pCPS )
            {
                strVal += QString( " [%1,1] CPS = %2\n" ).arg( i+1 ).arg( pCurList->sPolicy.pCPS );
            }

            if( pCurList->sPolicy.pUserNotice )
            {
                strVal += QString( " [%1,2] UserNotice = %2\n" ).arg( i+1 ).arg( pCurList->sPolicy.pUserNotice );
            }
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString("#OID$%1#CPS$%2#UserNotice$%3")
                .arg( pCurList->sPolicy.pOID )
                .arg( pCurList->sPolicy.pCPS )
                .arg( pCurList->sPolicy.pUserNotice );
        }

        pCurList = pCurList->pNext;
        i++;
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



static int _getSKI( const BIN *pBinExt, bool bShow, QString& strVal )
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

static int _getAKI( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    char    *pAKI = NULL;
    char    *pIssuer = NULL;
    char    *pSerial = NULL;

    ret = JS_PKI_getAuthorityKeyIdentifierValue( pBinExt, &pAKI, &pIssuer, &pSerial );

    if( bShow == true )
    {
        strVal = QString( "KeyID=%1\n").arg( pAKI );
        if( pIssuer ) strVal += QString( "CertificateIssuer=\n    %1\n").arg( pIssuer );
        if( pSerial ) strVal += QString( "CertificateSerialNumber=%1").arg( pSerial );
    }
    else
    {
        strVal = QString( "KEYID$%1#ISSUER$%2#SERIAL$%3").arg( pAKI ).arg( pIssuer ).arg( pSerial );
    }

    if( pAKI ) JS_free( pAKI );
    if( pIssuer ) JS_free( pIssuer );
    if( pSerial ) JS_free( pSerial );

    return 0;
}

static int _setEKU( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JStrList *pEKUList = NULL;

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

static int _getEKU( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    JStrList   *pEKUList = NULL;
    JStrList   *pCurList = NULL;

    ret = JS_PKI_getExtendedKeyUsageValue( pBinExt, &pEKUList );

    pCurList = pEKUList;

    while( pCurList )
    {
        if( strVal.length() > 0 ) strVal += ",";

        strVal += QString( pCurList->pStr );

        pCurList = pCurList->pNext;
    }

    if( pEKUList ) JS_UTIL_resetStrList( &pEKUList );
    return 0;
}

static int _setCRLDP( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JNameValList   *pDPList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i = 0; i < infoList.size(); i++ )
    {
        JNameVal sNameVal;
        QString info = infoList.at(i);
        QStringList typeData = info.split( "$" );

        if( typeData.size() < 2 ) continue;

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

static int _getCRLDP( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int i = 1;
    JNameValList   *pCRLDPList = NULL;
    JNameValList    *pCurList = NULL;

    ret = JS_PKI_getCRLDPValue( pBinExt, &pCRLDPList );

    pCurList = pCRLDPList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1] CRL Distribution Point\n" ).arg(i);
            strVal += QString( " %1=%2\n" ).arg( pCurList->sNameVal.pName ).arg( pCurList->sNameVal.pValue );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "#";

            strVal += QString( "%1$%2")
                .arg( pCurList->sNameVal.pName )
                .arg( pCurList->sNameVal.pValue );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pCRLDPList ) JS_UTIL_resetNameValList( &pCRLDPList );
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

static int _getBC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int nType = -1;
    int nPathLen = -1;

    QString strType;
    QString strPathLen;

    ret = JS_PKI_getBCValue( pBinExt, &nType, &nPathLen );

    if( nType == JS_PKI_BC_TYPE_CA )
        strType = "CA";
    else if( nType == JS_PKI_BC_TYPE_USER )
        strType = "EE";


    if( nPathLen >= 0 )
        strPathLen = QString("$PathLen:%1").arg( nPathLen );

    if( bShow )
    {
        strVal = QString( "SubjectType=%1\n").arg(strType);
        if( nPathLen >= 0 )
            strVal += QString( "PathLengthConstraint=%1" ).arg(nPathLen);
        else
            strVal += QString( "PathLengthConstraint=None" );
    }
    else
    {
        strVal += strType;
        strVal += strPathLen;
    }

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

        if( nameVal.size() < 2 ) continue;

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

static int _getPC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int nREP = -1;
    int nIPM = -1;

    ret = JS_PKI_getPolicyConstValue( pBinExt, &nREP, &nIPM );

    if( bShow )
    {
        if( nREP >= 0 ) strVal += QString("RequiredExplicitPolicySkipCerts=%1\n").arg( nREP );
        if( nIPM >= 0 ) strVal += QString("InhibitPolicyMappingSkipCerts=%1\n").arg( nIPM );
    }
    else
    {
        if( nREP >= 0 ) strVal += QString("#REP$%1").arg( nREP );
        if( nIPM >= 0 ) strVal += QString("#IPM$%1").arg( nIPM );
    }

    return 0;
}

static int _setAIA( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JExtAuthorityInfoAccessList *pAIAList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strType = "";
        QString strMethod = "";
        QString strMethodOID = "";
        QString strName = "";
        int nType = -1;

        JExtAuthorityInfoAccess sAIA;

        QString info = infoList.at(i);
        QStringList subList = info.split("$");

        if( subList.size() < 3 ) continue;

        memset( &sAIA, 0x00, sizeof(sAIA));

        strMethod = subList.at(0);
        strType = subList.at(1);
        strName = subList.at(2);

        if( strType == "URI" )
            nType = JS_PKI_NAME_TYPE_URI;
        else if( strType == "DNS" )
            nType = JS_PKI_NAME_TYPE_DNS;
        else if( strType == "email" )
            nType = JS_PKI_NAME_TYPE_EMAIL;

        if( strMethod.toUpper() == "CAISSUER" )
            strMethodOID = "1.3.6.1.5.5.7.48.2";
        else
            strMethodOID = "1.3.6.1.5.5.7.48.1";

        JS_PKI_setExtAuthorityInfoAccess( &sAIA,
                                          strMethodOID.toStdString().c_str(),
                                          nType,
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

static int _getAIA( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;
    JExtAuthorityInfoAccessList    *pAIAList = NULL;
    JExtAuthorityInfoAccessList    *pCurList = NULL;

    ret = JS_PKI_getAuthorityInfoAccessValue( pBinExt, &pAIAList );

    pCurList = pAIAList;

    while( pCurList )
    {
        QString strType;

        if( pCurList->sAuthorityInfoAccess.nType == JS_PKI_NAME_TYPE_DNS )
            strType = "DNS";
        else if( pCurList->sAuthorityInfoAccess.nType == JS_PKI_NAME_TYPE_URI )
            strType = "URI";
        else if( pCurList->sAuthorityInfoAccess.nType == JS_PKI_NAME_TYPE_EMAIL )
            strType = "Email";

        if( bShow )
        {
            strVal += QString( "[%1]Authority Info Access\n" ).arg(i);
            strVal += QString( " Access Method=%1\n").arg(pCurList->sAuthorityInfoAccess.pMethod);
            strVal += QString( " Alternative Name:\n" );
            strVal += QString( " %1=%2\n" ).arg(strType).arg(pCurList->sAuthorityInfoAccess.pName );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString( "Method$%1#Type$%2#Name$%3")
                .arg( pCurList->sAuthorityInfoAccess.pMethod )
                .arg( strType )
                .arg( pCurList->sAuthorityInfoAccess.pName );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pAIAList ) JS_PKI_resetExtAuthorityInfoAccessList( &pAIAList );
    return 0;
}

static int _setIDP( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JNumValList   *pIDPList = NULL;
    QStringList infoList = strVal.split("#");

    for( int i = 0; i < infoList.size(); i++ )
    {
        JNumVal sNumVal;

        QString info = infoList.at(i);
        QStringList typeVal = info.split("$");

        if( typeVal.size() < 2 ) continue;

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

static int _getIDP( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;

    JNumValList    *pIDPList = NULL;
    JNumValList    *pCurList = NULL;

    ret = JS_PKI_getIssuingDistPointValue( pBinExt, &pIDPList );

    pCurList = pIDPList;

    while( pCurList )
    {
        QString strType;

        if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_DNS )
            strType = "DNS";
        else if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_URI )
            strType = "URI";
        else if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_EMAIL )
            strType = "Email";

        if( bShow )
        {
            strVal += QString("[%1] Issuing Distribution Point:\n" ).arg(i);
            strVal += QString( " %1=%2\n" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }
        else
        {
            strVal += QString( "#%1$%2" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }

        pCurList = pCurList->pNext;
    }

    if( pIDPList ) JS_UTIL_resetNumValList( &pIDPList );
    return 0;
}

static int _setAltName( BIN *pBinExt, int nNid, const QString strVal )
{
    int ret = 0;
    JNumValList    *pNameList = NULL;
    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        JNumVal sNumVal;
        int nType = -1;

        QString info = infoList.at(i);
        QStringList typeVal = info.split( "$" );

        if( typeVal.size() < 2 ) continue;

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

static int _getAltName( const BIN *pBinExt, int nNid, bool bShow, QString& strVal )
{
    int     ret = 0;
    JNumValList    *pAltNameList = NULL;
    JNumValList    *pCurList = NULL;

    ret = JS_PKI_getAlternativNameValue( pBinExt, &pAltNameList );

    pCurList = pAltNameList;

    while( pCurList )
    {
        QString strType;
        if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_DNS )
            strType = "DNS";
        else if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_URI )
            strType = "URI";
        else if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_EMAIL )
            strType = "Email";

        if( bShow )
        {
            strVal += QString( "%1=%2\n" ).arg( strType ).arg( pCurList->sNumVal.pValue );
        }
        else
        {
            strVal += QString( "#%1$%2").arg( strType ).arg(pCurList->sNumVal.pValue);
        }

        pCurList = pCurList->pNext;
    }

    if( pAltNameList ) JS_UTIL_resetNumValList( &pAltNameList );
    return 0;
}

static int _setPM( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JExtPolicyMappingsList *pPMList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        JExtPolicyMappings sPM;

        QString info = infoList.at(i);
        QStringList valList = info.split("$");

        if( valList.size() < 2 ) continue;

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

static int _getPM( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int ret = 0;
    int i = 1;

    JExtPolicyMappingsList *pPMList = NULL;
    JExtPolicyMappingsList *pCurList = NULL;

    ret = JS_PKI_getPolicyMappingsValue( pBinExt, &pPMList );

    pCurList = pPMList;

    while( pCurList )
    {
        if( bShow )
        {
            strVal += QString( "[%1]Issuer Domain=%2\n" ).arg(i).arg(pCurList->sPolicyMappings.pIssuerDomainPolicy );
            if( pCurList->sPolicyMappings.pSubjectDomainPolicy )
                strVal += QString( " Subject Domain=%1\n" ).arg( pCurList->sPolicyMappings.pSubjectDomainPolicy );
        }
        else
        {
            if( strVal.length() > 0 ) strVal += "%%";

            strVal += QString( "IDP$%1#SDP$%2")
                .arg( pCurList->sPolicyMappings.pIssuerDomainPolicy )
                .arg( pCurList->sPolicyMappings.pSubjectDomainPolicy );
        }

        pCurList = pCurList->pNext;
        i++;
    }

    if( pPMList ) JS_PKI_resetExtPolicyMappingsList( &pPMList );
    return 0;
}

static int _setNC( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    JExtNameConstsList *pNCList = NULL;

    QStringList infoList = strVal.split("#");

    for( int i=0; i < infoList.size(); i++ )
    {
        JExtNameConsts sNC;

        int nMin = -1;
        int nMax = -1;
        int nType = -1;
        int nKind = -1;

        QString info = infoList.at(i);
        QStringList valList = info.split("$");

        if( valList.size() < 3 ) continue;

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

static int _getNC( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     pi = 1;
    int     ei = 1;

    JExtNameConstsList     *pNCList = NULL;
    JExtNameConstsList     *pCurList = NULL;

    ret = JS_PKI_getNameConstraintsValue( pBinExt, &pNCList );

    pCurList = pNCList;

    while( pCurList )
    {
        QString strType;
        if( pCurList->sNameConsts.nType == JS_PKI_NAME_TYPE_URI )
            strType = "URI";
        else if( pCurList->sNameConsts.nType == JS_PKI_NAME_TYPE_DNS )
            strType = "DNS";
        else if( pCurList->sNameConsts.nType == JS_PKI_NAME_TYPE_EMAIL )
            strType = "email";


        if( bShow )
        {
            if( pCurList->sNameConsts.nKind == JS_PKI_NAME_CONSTS_KIND_PST )
            {
                if( pi == 1 ) strVal += QString( "Permitted\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( pi ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1=%2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                pi++;
            }
            else
            {
                if( ei == 1 ) strVal += QString( "Excluded\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( ei ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1=%2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                ei++;
            }
        }
        else
        {
            strVal += QString("#%1$%2$%3$%4$%5")
                .arg( pCurList->sNameConsts.nKind )
                .arg( pCurList->sNameConsts.nType )
                .arg(pCurList->sNameConsts.pValue )
                .arg(pCurList->sNameConsts.nMin )
                .arg(pCurList->sNameConsts.nMax );
        }

        pCurList = pCurList->pNext;
    }

    return 0;
}

static int _setCRLReason( BIN *pBinExt, const QString strVal )
{
    int ret = 0;
    int nReason = strVal.toInt();

    ret = JS_PKI_setCRLReasonValue( pBinExt, nReason );

    return ret;
}

static int _getCRLReason( const BIN *pBinExt, bool bShow, QString& strVal )
{
    int     ret = 0;
    int     nReason = -1;

    ret = JS_PKI_getCRLReasonValue( pBinExt, &nReason );

    if( nReason > 0 ) strVal = crl_reasons[nReason];

    return 0;
}

static int _setOctet( BIN *pBinExt, const QString strVal )
{
    int ret = 0;

    ret = JS_PKI_setOctetValue( pBinExt, strVal.toStdString().c_str() );

    return ret;
}

static int _getOctet( const BIN *pBinExt, QString& strVal )
{
    int ret = 0;
    char        *pSKI = NULL;

    ret = JS_PKI_getOctetValue( pBinExt, &pSKI );

    if( pSKI )
    {
        strVal = pSKI;
        JS_free( pSKI );
    }

    return 0;
}

QString findFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

//    QString strPath = QDir::currentPath();

    QString strType;
    QString selectedFilter;

    if( nType == JS_FILE_TYPE_CERT )
        strType = QObject::tr("Cert Files (*.crt *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_PRIKEY )
        strType = QObject::tr("Key Files (*.key *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_TXT )
        strType = QObject::tr("TXT Files (*.txt *.log);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_BER )
        strType = QObject::tr("BER Files (*.ber *.der *.pem);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_DB )
        strType = QObject::tr("DB Files (*.db *db3 *.xdb);;All Files(*.*)");
    else if( nType == JS_FILE_TYPE_DLL )
        strType = QObject::tr( "DLL Files (*.dll);;SO Files (*.so);;All Files (*.*)" );

    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strCurPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
};


int transExtInfoFromDBRec( JExtensionInfo *pExtInfo, ProfileExtRec profileExtRec )
{
    int ret = 0;
    BIN binExt = {0,0};
    char sOID[1024];
    char *pHexVal = NULL;

    bool bCrit = profileExtRec.isCritical();
    QString strSN = profileExtRec.getSN();
    QString strVal = profileExtRec.getValue();

    memset( sOID, 0x00, sizeof(sOID) );

    ret = JS_PKI_getOIDFromSN( strSN.toStdString().c_str(), sOID );
    if( ret != 0 )
    {
        sprintf( sOID, "%s", strSN.toStdString().c_str() );
    }

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
//        ret = _setOctet( &binExt, strVal );
        ret = JS_BIN_decodeHex( strVal.toStdString().c_str(), &binExt );
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

int transExtInfoToDBRec( const JExtensionInfo *pExtInfo, ProfileExtRec& profileExtRec )
{
    int ret = 0;
    QString strVal = "";
    QString strSN = pExtInfo->pOID;
    BIN     binExt = {0,0};

    JS_BIN_decodeHex( pExtInfo->pValue, &binExt );

    if( strSN == kExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, false, strVal );
    }
    else if( strSN == kExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, false, strVal );
    }
    else if( strSN == kExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, false, strVal );
    }
    else if( strSN == kExtNameSKI )
    {
        ret = _getSKI( &binExt, false, strVal );
    }
    else if( strSN == kExtNameAKI )
    {
        ret = _getAKI( &binExt, false, strVal );
    }
    else if( strSN == kExtNameEKU )
    {
        ret = _getEKU( &binExt, false, strVal );
    }
    else if( strSN == kExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, false, strVal );
    }
    else if( strSN == kExtNameBC )
    {
        ret = _getBC( &binExt, false, strVal );
    }
    else if( strSN == kExtNamePC )
    {
        ret = _getPC( &binExt, false, strVal );
    }
    else if( strSN == kExtNameAIA )
    {
        ret = _getAIA( &binExt, false, strVal );
    }
    else if( strSN == kExtNameIDP )
    {
        ret = _getIDP( &binExt, false, strVal );
    }
    else if( strSN == kExtNameSAN || strSN == kExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, false, strVal );
    }
    else if( strSN == kExtNamePM )
    {
        ret = _getPM( &binExt, false, strVal );
    }
    else if( strSN == kExtNameNC )
    {
        ret = _getNC( &binExt, false, strVal );
    }
    else if( strSN == kExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, false, strVal );
    }
    else
    {
//        ret = _getOctet( &binExt, strVal );
        strVal = pExtInfo->pValue;
    }

    profileExtRec.setSN( strSN );
    profileExtRec.setCritical( pExtInfo->bCritical );
    profileExtRec.setValue( strVal );

    JS_BIN_reset( &binExt );

    return 0;
}

void getInfoValue( const JExtensionInfo *pExtInfo, QString& strVal )
{
    int ret = 0;
    QString strSN = pExtInfo->pOID;
    BIN     binExt = {0,0};

    JS_BIN_decodeHex( pExtInfo->pValue, &binExt );

    if( strSN == kExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, true, strVal );
    }
    else if( strSN == kExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, true, strVal );
    }
    else if( strSN == kExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, true, strVal );
    }
    else if( strSN == kExtNameSKI )
    {
        ret = _getSKI( &binExt, true, strVal );
    }
    else if( strSN == kExtNameAKI )
    {
        ret = _getAKI( &binExt, true, strVal );
    }
    else if( strSN == kExtNameEKU )
    {
        ret = _getEKU( &binExt, true, strVal );
    }
    else if( strSN == kExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, true, strVal );
    }
    else if( strSN == kExtNameBC )
    {
        ret = _getBC( &binExt, true, strVal );
    }
    else if( strSN == kExtNamePC )
    {
        ret = _getPC( &binExt, true, strVal );
    }
    else if( strSN == kExtNameAIA )
    {
        ret = _getAIA( &binExt, true, strVal );
    }
    else if( strSN == kExtNameIDP )
    {
        ret = _getIDP( &binExt, true, strVal );
    }
    else if( strSN == kExtNameSAN || strSN == kExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, true, strVal );
    }
    else if( strSN == kExtNamePM )
    {
        ret = _getPM( &binExt, true, strVal );
    }
    else if( strSN == kExtNameNC )
    {
        ret = _getNC( &binExt, true, strVal );
    }
    else if( strSN == kExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, true, strVal );
    }
    else
    {
        strVal = pExtInfo->pValue;
    }

    JS_BIN_reset( &binExt );
}

CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotID )
{
    PinDlg pinDlg;
    QString strPin;

    JP11_CTX    *pCTX = (JP11_CTX *)pP11CTX;

    int nFlags = 0;

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;


    int ret = pinDlg.exec();
    if( ret == QDialog::Accepted )
    {
        strPin = pinDlg.getPinText();
    }
    else
    {
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( pCTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 || uSlotCnt < nSlotID )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( pCTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( pCTX, nUserType, (CK_UTF8CHAR *)strPin.toStdString().c_str(), strPin.length() );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    return pCTX->hSession;
}

int getKMIPConnection( SettingsMgr* settingMgr, SSL_CTX **ppCTX, SSL **ppSSL, Authentication **ppAuth )
{
    int ret = 0;
    BIN binCACert = {0,0};
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};

    SSL_CTX *pCTX = NULL;
    SSL     *pSSL = NULL;
    Authentication *pAuth = NULL;

    if( settingMgr == NULL ) return -1;

    bool bVal = settingMgr->KMIPUse();

    if( bVal == false ) return -1;


    QString strHost = settingMgr->KMIPHost();
    QString strPort = settingMgr->KMIPPort();
    QString strCACertPath = settingMgr->KMIPCACertPath();
    QString strCertPath = settingMgr->KMIPCertPath();
    QString strPriKeyPath = settingMgr->KMIPPrivateKeyPath();
    QString strUserName = settingMgr->KMIPUserName();
    QString strPasswd = settingMgr->KMIPPasswd();

    if( strUserName.length() > 0 )
    {
        pAuth = (Authentication *)JS_calloc(1, sizeof(Authentication));

        JS_KMS_makeAuthentication( strUserName.toStdString().c_str(), strPasswd.toStdString().c_str(), pAuth );
    }

    JS_BIN_fileRead( strCACertPath.toLocal8Bit().toStdString().c_str(), &binCACert );
    JS_BIN_fileRead( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_BIN_fileRead( strPriKeyPath.toLocal8Bit().toStdString().c_str(), &binPriKey );


    JS_SSL_initClient( &pCTX );
    JS_SSL_setClientCACert( pCTX, &binCACert );
    JS_SSL_setCertAndPriKey( pCTX, &binPriKey, &binCert );

    JS_SSL_connect( pCTX, strHost.toStdString().c_str(), strPort.toInt(), &pSSL );
    if( pSSL == NULL )
    {
        ret = -1;
        goto end;
    }

    *ppCTX = pCTX;
    *ppSSL = pSSL;
    *ppAuth = pAuth;

end :
    JS_BIN_reset( &binCACert );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );

    return ret;
}

int genKeyPairWithP11( JP11_CTX *pCTX, int nSlotID, QString strPin, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub )
{
    JP11_CTX   *pP11CTX = NULL;

    int rv;

    pP11CTX = pCTX;

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

    BIN binLabel = {0,0};
    JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.length() );


    BIN binPubExponent = {0,0};
    BIN binGroup = {0,0};
    CK_ULONG	uModBitLen = 0;

    BIN binVal = {0,0};
    BIN binHash = {0,0};

    memset( &sMech, 0x00, sizeof(sMech) );

    if( strAlg == kMechPKCS11_RSA )
    {
        sMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        keyType = CKK_RSA;
    }
    else if( strAlg == kMechPKCS11_EC )
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
        strDecimal.sprintf( "%d", nExponent );
        JS_PKI_decimalToBin( strDecimal.toStdString().c_str(), &binPubExponent );

        sPubTemplate[uPubCount].type = CKA_PUBLIC_EXPONENT;
        sPubTemplate[uPubCount].pValue = binPubExponent.pVal;
        sPubTemplate[uPubCount].ulValueLen = binPubExponent.nLen;
        uPubCount++;

        uModBitLen = strParam.toInt();

        sPubTemplate[uPubCount].type = CKA_MODULUS_BITS;
        sPubTemplate[uPubCount].pValue = &uModBitLen;
        sPubTemplate[uPubCount].ulValueLen = sizeof( uModBitLen );
        uPubCount++;
    }
    else if( keyType == CKK_ECDSA )
    {
        char    sHexOID[128];
        memset( sHexOID, 0x00, sizeof(sHexOID));

        JS_PKI_getHexOIDFromSN( strParam.toStdString().c_str(), sHexOID );
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

        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_MODULUS, &binVal );
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
        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_EC_POINT, &binVal );
        if( rv != 0 ) goto end;

        char *pPubX = NULL;
        char *pPubY = NULL;
        char *pGroup = NULL;

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        BIN binKey = {0,0};
        BIN binPubX = {0,0};
        BIN binPubY = {0,0};

        JS_BIN_set( &binKey, binVal.pVal + 1, binVal.nLen - 1 );
        JS_BIN_set( &binPubX, &binKey.pVal[0], binKey.nLen/2 );
        JS_BIN_set( &binPubY, &binKey.pVal[binKey.nLen/2], binKey.nLen/2 );


        JS_BIN_encodeHex( &binGroup, &pGroup );
        JS_BIN_encodeHex( &binPubX, &pPubX );
        JS_BIN_encodeHex( &binPubY, &pPubY );

        JS_PKI_setECKeyVal( &ecKey, pGroup, pPubX, pPubX, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub );

        if( pGroup ) JS_free( pGroup );
        if( pPubX ) JS_free( pPubX );
        if( pPubY ) JS_free( pPubY );
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

int genKeyPairWithKMIP( SettingsMgr* settingMgr, QString strAlg, QString strParam, BIN *pPri, BIN *pPub )
{
    int ret = 0;
    Authentication *pAuth = NULL;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    SSL_CTX *pCTX = NULL;
    SSL *pSSL = NULL;
    BIN binData = {0,0};


    int nAlg = JS_PKI_KEY_TYPE_RSA;
    int nParam = 0;
    int nType = -1;

    if( strAlg == kMechKMIP_RSA )
    {
        nAlg = JS_PKI_KEY_TYPE_RSA;
        nParam = strParam.toInt();
    }
    else if( strAlg == kMechKMIP_EC )
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
    char *pPriUUID2 = NULL;
    char *pPubUUID2 = NULL;

    ret = getKMIPConnection( settingMgr, &pCTX, &pSSL, &pAuth );
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

    ret = getKMIPConnection( settingMgr, &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    ret = JS_KMS_encodeActivateReq( pAuth, pPriUUID, &binReq );
    ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    ret = JS_KMS_decodeActivateRsp( &binRsp, &pPriUUID2 );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_SSL_clear( pSSL );
    pSSL = NULL;

    ret = getKMIPConnection( settingMgr, &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    ret = JS_KMS_encodeActivateReq( pAuth, pPubUUID, &binReq );
    ret = JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    ret = JS_KMS_decodeActivateRsp( &binRsp, &pPubUUID2 );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_SSL_clear( pSSL );
    pSSL = NULL;

    ret = getKMIPConnection( settingMgr, &pCTX, &pSSL, &pAuth );
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
        JS_BIN_copy( pPub, &binData );
    }
    else if( nAlg == JS_PKI_KEY_TYPE_ECC )
    {
        BIN binGroup = {0,0};

        char *pGroup = NULL;
        char *pPubX = NULL;
        char *pPubY = NULL;

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        char    sHexOID[128];
        memset( sHexOID, 0x00, sizeof(sHexOID));

        JS_PKI_getHexOIDFromSN( "prime256v1", sHexOID );
        JS_BIN_decodeHex( sHexOID, &binGroup );

        BIN binKey = {0,0};
        BIN binPubX = {0,0};
        BIN binPubY = {0,0};

        JS_BIN_set( &binKey, binData.pVal + 1, binData.nLen - 1 );
        JS_BIN_set( &binPubX, &binKey.pVal[0], binKey.nLen/2);
        JS_BIN_set( &binPubY, &binKey.pVal[binKey.nLen/2], binKey.nLen/2 );


        JS_BIN_encodeHex( &binGroup, &pGroup );
        JS_BIN_encodeHex( &binPubX, &pPubX );
        JS_BIN_encodeHex( &binPubY, &pPubY );


        JS_PKI_setECKeyVal( &ecKey, pGroup, pPubX, pPubY, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub );


        if( pGroup ) JS_free( pGroup );
        if( pPubX ) JS_free( pPubX );
        if( pPubY ) JS_free( pPubY );

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binPubX );
        JS_BIN_reset( &binPubY );
        JS_BIN_reset( &binGroup );
        JS_PKI_resetECKeyVal( &ecKey );
    }

    JS_BIN_set( pPri, (unsigned char *)pPriUUID, strlen( pPriUUID ) );

 end :
    if( pPubUUID ) JS_free( pPubUUID );
    if( pPriUUID ) JS_free( pPriUUID );
    if( pPubUUID2 ) JS_free( pPubUUID2 );
    if( pPriUUID2 ) JS_free( pPriUUID2 );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth )
    {
        JS_KMS_resetAuthentication( pAuth );
        JS_free( pAuth );
    }

    return ret;
}


int addAudit( DBMgr *dbMgr, int nKind, int nOP, QString strInfo )
{
    AuditRec auditRec;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHMAC = {0,0};

    char *pHex = NULL;

    if( dbMgr == NULL ) return -1;

    int nSeq = dbMgr->getSeq( "TB_AUDIT" );
    nSeq++;

    auditRec.setSeq( nSeq );
    auditRec.setKind( nKind );
    auditRec.setOperation( nOP );
    auditRec.setInfo( strInfo );
    auditRec.setRegTime( time(NULL) );
    auditRec.setUserName( "admin" );

    binKey.pVal = (unsigned char *)JS_GEN_HMAC_KEY;
    binKey.nLen = strlen( JS_GEN_HMAC_KEY );

    QString strSrc = QString( "%1_%2_%3_%4_%5_%6" )
            .arg( nSeq)
            .arg( nKind )
            .arg( nOP )
            .arg( strInfo )
            .arg( auditRec.getRegTime() )
            .arg( auditRec.getUserName() );

    binSrc.pVal = (unsigned char *)strSrc.toStdString().c_str();
    binSrc.nLen = strSrc.length();

    JS_PKI_genHMAC( "SHA256", &binSrc, &binKey, &binHMAC );

    JS_BIN_encodeHex( &binHMAC, &pHex );
    if( pHex )
    {
        auditRec.setMAC( pHex );
        dbMgr->addAuditRec( auditRec );
        JS_free( pHex );
    }

    JS_BIN_reset( &binHMAC );

    return 0;
}

int verifyAuditRec( AuditRec audit )
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHMAC = {0,0};
    BIN binRecHMAC = {0,0};

    binKey.pVal = (unsigned char *)JS_GEN_HMAC_KEY;
    binKey.nLen = strlen( JS_GEN_HMAC_KEY );

    QString strSrc = QString( "%1_%2_%3_%4_%5_%6" )
            .arg( audit.getSeq() )
            .arg( audit.getKind() )
            .arg( audit.getOperation() )
            .arg( audit.getInfo() )
            .arg( audit.getRegTime() )
            .arg( audit.getUserName() );

    binSrc.pVal = (unsigned char *)strSrc.toStdString().c_str();
    binSrc.nLen = strSrc.length();

    ret = JS_PKI_genHMAC( "SHA256", &binSrc, &binKey, &binHMAC );
    if( ret != 0 ) return -1;

    JS_BIN_decodeHex( audit.getMAC().toStdString().c_str(), &binRecHMAC );

    ret = JS_BIN_cmp( &binHMAC, &binRecHMAC );

    JS_BIN_reset( &binHMAC );
    JS_BIN_reset( &binRecHMAC );

    return ret;
}

int writeCertDB( DBMgr *dbMgr, const BIN *pCert )
{
    int nRet = 0;
    JCertInfo   sCertInfo;
    char *pHex = NULL;
    CertRec certRec;

    if( pCert == NULL || dbMgr == NULL ) return -1;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    nRet = JS_PKI_getCertInfo( pCert, &sCertInfo, NULL );
    if( nRet != 0 )
    {
        fprintf( stderr, "fail to parse certificate : %d\n", nRet );
        nRet = -1;
        goto end;
    }

    JS_BIN_encodeHex( pCert, &pHex );

    certRec.setCert( pHex );
    certRec.setRegTime( time(NULL));
    certRec.setKeyNum( -1 );
    certRec.setSubjectDN( sCertInfo.pSubjectName );
    certRec.setIssuerNum( -2 );
    certRec.setSignAlg( sCertInfo.pSignAlgorithm );
    dbMgr->addCertRec( certRec );

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pHex ) JS_free( pHex );

    return nRet;
}

int writeCRLDB( DBMgr *dbMgr, const BIN *pCRL )
{
    int nRet = 0;
    int nSeq = 0;
    JCRLInfo sCRLInfo;
    CRLRec crlRec;
    char *pHex = NULL;

    if( pCRL == NULL ) return -1;

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    nRet = JS_PKI_getCRLInfo( pCRL, &sCRLInfo, NULL, NULL );
    if( nRet != 0 )
    {
        fprintf( stderr, "fail to parse crl data : %d\n", nRet);
        goto end;
    }

    nSeq = dbMgr->getSeq( "TB_CRL" );
    nSeq++;

    JS_BIN_encodeHex( pCRL, &pHex );

    crlRec.setNum( nSeq );
    crlRec.setRegTime( time(NULL));
    crlRec.setIssuerNum( -2 );
    crlRec.setSignAlg( sCRLInfo.pSignAlgorithm );
    crlRec.setCRL( pHex );

    dbMgr->addCRLRec( crlRec );

end:
    JS_PKI_resetCRLInfo( &sCRLInfo );
    if( pHex ) JS_free( pHex );

    return nRet;
}

int writeCSRDB( DBMgr *dbMgr, int nKeyNum, const char *pName, const char *pDN, const char *pHash, const BIN *pCSR )
{
    int seq = 0;
    ReqRec  req;
    char *pHexCSR = NULL;

    seq = dbMgr->getSeq( "TB_REQ" );
    seq++;

    JS_BIN_encodeHex( pCSR, &pHexCSR );

    req.setSeq( seq );
    req.setRegTime( time(NULL) );
    req.setKeyNum( nKeyNum );
    req.setName( pName );
    req.setDN( pDN );
    req.setHash( pHash );
    req.setCSR( pHexCSR );
    req.setStatus( 0 );

    dbMgr->addReqRec( req );
    if( pHexCSR ) JS_free( pHexCSR );

    return seq;
}

int writeKeyPairDB( DBMgr *dbMgr, const char *pName, const BIN *pPub, const BIN *pPri )
{
    int ret = 0;
    int seq = -1;
    int nType = -1;
    int nOption = -1;
    QString strAlg;
    QString strParam;
    char *pPubHex = NULL;
    char *pPriHex = NULL;

    KeyPairRec  keyPair;

    seq = dbMgr->getSeq( "TB_KEY_PAIR" );
    seq++;

    ret = JS_PKI_getPubKeyInfo( pPub, &nType, &nOption );
    if( ret != 0 ) return -1;

    if( nType == JS_PKI_KEY_TYPE_RSA )
    {
        strAlg = "RSA";
        strParam = QString( "%1" ).arg( nOption );
    }
    else if( nType == JS_PKI_KEY_TYPE_ECC )
    {
        strAlg = "ECC";
        strParam = JS_PKI_getSNFromNid( nOption );
    }
    else {
        return -1;
    }

    JS_BIN_encodeHex( pPub, &pPubHex );
    JS_BIN_encodeHex( pPri, &pPriHex );

    keyPair.setNum( seq );
    keyPair.setAlg( strAlg );
    keyPair.setParam( strParam );
    keyPair.setName( pName );
    keyPair.setRegTime( time(NULL) );
    keyPair.setStatus( 0 );

    keyPair.setPublicKey( pPubHex );
    keyPair.setPrivateKey( pPriHex );

    dbMgr->addKeyPairRec( keyPair );

    if( pPubHex ) JS_free( pPubHex );
    if( pPriHex ) JS_free( pPriHex );

    return seq;
}

QString findPath(int bPri, QWidget *parent )
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;


    QString strPath = QDir::currentPath();

    QString strType;
    QString selectedFilter;

    if( bPri )
        strType = QObject::tr( "Key Files (*.key);;DER Files (*.der);;All Files(*.*)");
    else
        strType = QObject::tr("Cert Files (*.crt);;DER Files (*.der);;All Files(*.*)");

    QString fileName = QFileDialog::getOpenFileName( parent,
                                                     QObject::tr( "Open File" ),
                                                     strPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    return fileName;
}

void CMPSetTrustList( SettingsMgr *settingMgr, BINList **ppTrustList )
{
    BINList     *pBinList = NULL;

    BIN binRootCA = {0,0};
    BIN binCA = {0,0};

    QString strRootCAPath = settingMgr->CMPRootCACertPath();
    QString strCAPath = settingMgr->CMPCACertPath();

    JS_BIN_fileRead( strRootCAPath.toLocal8Bit().toStdString().c_str(), &binRootCA );
    JS_BIN_fileRead( strCAPath.toLocal8Bit().toStdString().c_str(), &binCA );

    JS_BIN_createList( &binRootCA, &pBinList );
    JS_BIN_appendList( pBinList, &binCA );

    JS_BIN_reset( &binRootCA );
    JS_BIN_reset( &binCA );

    *ppTrustList = pBinList;
}

QString getDateTime( time_t tTime )
{
    QDateTime dateTime;
    dateTime.setTime_t( tTime );

    return dateTime.toString( "yyyy-MM-dd HH:mm:ss");
}

QString getRecStatusName( int nStatus )
{
    if( nStatus == JS_REC_STATUS_NOT_USED )
        return "NotUsed";
    else if( nStatus == JS_REC_STATUS_USED )
        return "Used";

    return "Unknown";
}

QString getAdminTypeName( int nType )
{
    if( nType == JS_ADMIN_TYPE_INVALID )
        return "Invalid";
    else if( nType == JS_ADMIN_TYPE_MASTER )
        return "Master";
    else if( nType == JS_ADMIN_TYPE_ADMIN )
        return "Admin";
    else if( nType == JS_ADMIN_TYPE_AUDIT )
        return "Audit";

    return "Unknown";
}

QString getStatusName( int nStatus )
{
    if( nStatus == JS_STATUS_INVALID )
        return "Invalid";
    else if( nStatus == JS_STATUS_STOP )
        return "Stop";
    else if( nStatus == JS_STATUS_VALID )
        return "Valid";

    return "Unknown";
}

QString getStateName( int nState )
{

}

QString getUserStatusName( int nStatus )
{
    if( nStatus == JS_USER_STATUS_INVALID )
        return "Invalid";
    else if( nStatus == JS_USER_STATUS_REGISTER )
        return "Register";
    else if( nStatus == JS_USER_STATUS_ISSUED )
        return "Issued";
    else if( nStatus == JS_USER_STATUS_STOP )
        return "Stop";

    return "Unknown";
}

QString getSignerTypeName( int nType )
{
    if( nType == JS_SIGNER_TYPE_REG )
        return "RegSigner";
    else if( nType == JS_SIGNER_TYPE_OCSP )
        return "OCSPSigner";

    return "Unknown";
}

QString getCertStatusName( int nStatus )
{
    if( nStatus == JS_CERT_STATUS_INVALID )
        return "Invalid";
    else if( nStatus == JS_CERT_STATUS_GOOD )
        return "Good";
    else if( nStatus == JS_CERT_STATUS_REVOKE )
        return "Revoke";
    else if( nStatus == JS_CERT_STATUS_HOLD )
        return "Hold";

    return "Unknown";
}

QString getCertStatusSName( int nStatus )
{
    if( nStatus == JS_CERT_STATUS_INVALID )
        return "I";
    else if( nStatus == JS_CERT_STATUS_GOOD )
        return "G";
    else if( nStatus == JS_CERT_STATUS_REVOKE )
        return "R";
    else if( nStatus == JS_CERT_STATUS_HOLD )
        return "H";

    return "Unknown";
}

QString getRevokeReasonName( int nReason )
{
    return kRevokeReasonList.at( nReason );
}
