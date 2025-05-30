/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QObject>
#include <QString>
#include <QtCore>
#include <QFileDialog>
#include <QRegularExpression>
#include <QProcess>
#include <QNetworkInterface>

#include "commons.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "js_pki_eddsa.h"
#include "js_util.h"
#include "pin_dlg.h"
#include "audit_rec.h"
#include "js_gen.h"
#include "js_define.h"


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

static const QString _getKeyUsageProfile( const QString strVal )
{
    QString strShow;
    QStringList valList = strVal.split( "#" );

    for( int i = 0; i < valList.size(); i++ )
    {
        QString strOne = valList.at(i);

        if( i != 0 ) strShow += ",";
        strShow += strOne;
    }

    strShow += "\n";

    return strShow;
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
            strVal = QString( "CRL Number=0x%1" ).arg( pCRLNum );
        else
            strVal = pCRLNum;

        JS_free( pCRLNum );
    }

    return 0;
}

static const QString _getCRLNumProfile( const QString strVal )
{
    QString strShow;

    if( strVal == "auto" )
        strShow = QString( "CRLNumber = [variable]\n" );
    else
        strShow = QString( "CRLNumber = %1 (%2 Hex)\n" ).arg( strVal.toInt() ).arg( strVal.toInt(), 0, 16);

    return strShow;
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

static const QString _getCertPolicyProfile( const QString strVal )
{
    QString strShow;

    QStringList valList = strVal.split( "%%" );

    for( int i = 0; i < valList.size(); i++ )
    {
        QString infoVal = valList.at(i);
        QStringList infoList = infoVal.split( "#" );

        strShow += QString( "[%1]Certificate Policy:\n" ).arg(i+1);

        for( int k = 0; k < infoList.size(); k++ )
        {
            QString oneVal = infoList.at(k);
            QStringList oneList = oneVal.split( "$" );
            if( oneList.size() < 2 ) continue;
            QString strT = oneList.at(0);
            QString strV = oneList.at(1);

            if( strT == "OID" )
            {
                strShow += QString( " Policy Identifier=%1\n" ).arg( strV );
            }
            else if( strT == "CPS" )
            {
                strShow += QString( " [%1,1] CPS = %2\n" ).arg( i+1 ).arg( strV );
            }
            else if( strT == "UserNotice" )
            {
                strShow += QString( " [%1,2] UserNotice = %2\n" ).arg( i+1 ).arg( strV );
            }
        }
    }

    return strShow;
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

static const QString _getSKIProfile( const QString strVal )
{
    QString strShow = "keyIdentifier = [variable]\n";
    return strShow;
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

static const QString _getAKIProfile( const QString strVal )
{
    QString strShow;

    QStringList valList = strVal.split( "#" );

    strShow = "IssuerKeyIdentifier = [variable]\n";

    for( int i = 0; i < valList.size(); i++ )
    {
        QString strOne = valList.at(i);

        if( strOne == "ISSUER" )
            strShow += " CertificateIssuer = [variable]\n";
        else if( strOne == "SERIAL" )
            strShow += " CertificateSerialNumber = [variable]\n";
    }

    return strShow;
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

static const QString _getEKUProfile( const QString strVal )
{
    QString strShow;
    QStringList valList = strVal.split( "#" );

    for( int i = 0; i < valList.size(); i++ )
    {
        QString strOne = valList.at(i);

        if( i != 0 ) strShow += ",";
        strShow += strOne;
    }

    strShow += "\n";

    return strShow;
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

static const QString _getCRLDPProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );
        if( partList.size() < 2 ) continue;

        strShow += QString( "[%1] CRL Distribution Point\n" ).arg(i);
        strShow += QString( " %1=%2\n" ).arg( partList.at(0) ).arg( partList.at(1) );
    }

    return strShow;
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

static const QString _getBCProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    if( infoList.size() < 1 ) return strShow;

    QString strType = infoList.at(0);
    strShow += QString( "SubjectType=%1\n").arg(strType);

    if( strType == "CA" )
    {
        if( infoList.size() > 1 )
        {
            int nPathLen = infoList.at(1).toInt();
            strShow += QString( "PathLengthConstraint=%1\n" ).arg(nPathLen);
        }
        else
        {
            strShow = QString( "PathLengthConstraint=None\n" );
        }
    }

    return strShow;
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

static const QString _getPCProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );

        if( partList.size() < 2 ) continue;

        QString strType = partList.at(0);
        QString strNum = partList.at(1);

        if( strType == "REP" )
            strShow += QString("RequiredExplicitPolicySkipCerts=%1\n").arg( strNum );
        else if( strType == "IPM" )
            strShow += QString("InhibitPolicyMappingSkipCerts=%1\n").arg( strNum );
    }

    return strShow;
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

        nType = JS_PKI_getGenNameType( strType.toStdString().c_str() );

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
        QString strType = JS_PKI_getGenNameString( pCurList->sAuthorityInfoAccess.nType );

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

static const QString _getAIAProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );

        if( partList.size() < 3 ) continue;

        QString strMethod = partList.at(0);
        QString strType = partList.at(1);
        QString strName = partList.at(2);

        strShow += QString( "[%1]Authority Info Access\n" ).arg(i);
        strShow += QString( " Access Method=%1\n").arg( strMethod );
        strShow += QString( " Alternative Name:\n" );
        strShow += QString( " %1=%2\n" ).arg(strType).arg( strName );
    }

    return strShow;
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
        QString strType = JS_PKI_getGenNameString( pCurList->sNumVal.nNum );

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

static const QString _getIDPProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );

        if( partList.size() < 2 ) continue;

        QString strType = partList.at(0);
        QString strDP = partList.at(1);

        strShow += QString("[%1] Issuing Distribution Point:\n" ).arg(i);
        strShow += QString( " %1=%2\n" ).arg( strType ).arg( strDP );
    }

    return strShow;
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
        nType = JS_PKI_getGenNameType( type.toStdString().c_str() );

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
        QString strType = JS_PKI_getGenNameString( pCurList->sNumVal.nNum );

        if( bShow )
        {
            if( pCurList->sNumVal.nNum == JS_PKI_NAME_TYPE_OTHERNAME )
                strVal += QString( "%1: %2\n").arg( strType ).arg( pCurList->sNumVal.pValue );
            else
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

static const QString _getAltNameProfile( int nNid, const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );

        if( partList.size() < 2 ) continue;

        QString strType = partList.at(0);
        QString strName = partList.at(1);

        strShow += QString( "%1 : %2\n" ).arg( strType ).arg( strName );
    }

    return strShow;
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

static const QString _getPMProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );

        if( partList.size() < 2 ) continue;

        QString strType = partList.at(0);
        QString strOID = partList.at(1);

        if( strType == "IDP" )
            strShow += QString( "[%1]Issuer Domain=%2\n" ).arg(i).arg( strOID );
        else if( strType == "SDP" )
            strShow += QString( " Subject Domain=%1\n" ).arg( strOID );
    }

    return strShow;
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

        nType = JS_PKI_getGenNameType( strType.toStdString().c_str() );

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
        QString strType = JS_PKI_getGenNameString( pCurList->sNameConsts.nType );

        if( bShow )
        {
            if( pCurList->sNameConsts.nKind == JS_PKI_NAME_CONSTS_KIND_PST )
            {
                if( pi == 1 ) strVal += QString( "Permitted\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( pi ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1 : %2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

                pi++;
            }
            else
            {
                if( ei == 1 ) strVal += QString( "Excluded\n" );
                strVal += QString( " [%1]Subtrees(%2..%3)\n" ).arg( ei ).arg( pCurList->sNameConsts.nMax ).arg( pCurList->sNameConsts.nMin );
                strVal += QString( "  %1 : %2\n" ).arg( strType ).arg( pCurList->sNameConsts.pValue );

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

static const QString _getNCProfile( const QString strVal )
{
    QString strShow;
    QStringList infoList = strVal.split( "#" );
    int pi = 1;
    int ei = 1;

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );

        if( partList.size() < 3 ) continue;

        QString strType = partList.at(0);
        QString strKind = partList.at(1);
        QString strData = partList.at(2);
        QString strMin;
        QString strMax;

        if( partList.size() >= 5 )
        {
            strMin = partList.at(3);
            strMax = partList.at(4);
        }

        if( strKind == "permittedSubtrees" )
        {
            if( pi == 1 ) strShow += QString( "Permitted\n" );
            strShow += QString( " [%1]Subtrees(%2..%3)\n" ).arg( pi ).arg( strMax ).arg( strMin );
            strShow += QString( "  %1 : %2\n" ).arg( strType ).arg( strData );

            pi++;
        }
        else if( strKind == "excludedSubtrees" )
        {
            if( ei == 1 ) strShow += QString( "Excluded\n" );
            strShow += QString( " [%1]Subtrees(%2..%3)\n" ).arg( ei ).arg( strMax ).arg( strMin );
            strShow += QString( "  %1 : %2\n" ).arg( strType ).arg( strData );

            ei++;
        }
    }

    return strShow;
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

    if( nReason >= 0 ) strVal = crl_reasons[nReason];

    return 0;
}

static const QString _getCRLReasonProfile( const QString strVal )
{
    QString strShow;

    strShow = QString( "%1\n" ).arg( strVal );

    return strShow;
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

const QString GetSystemID()
{
    QString strID;

#ifdef Q_OS_MACOS
    QProcess proc;
    QStringList args;
    args << "-c" << "ioreg -rd1 -c IOPlatformExpertDevice |  awk '/IOPlatformSerialNumber/ { print $3; }'";
    proc.start( "/bin/bash", args );
    proc.waitForFinished();
    QString uID = proc.readAll();
    uID.replace( "\"", "" );

    strID = uID.trimmed();
#else

    foreach( QNetworkInterface netIFT, QNetworkInterface::allInterfaces() )
    {
        if( !(netIFT.flags() & QNetworkInterface::IsLoopBack) )
        {
            if( netIFT.flags() & QNetworkInterface::IsUp )
            {
                if( netIFT.flags() & QNetworkInterface::Ethernet || netIFT.flags() & QNetworkInterface::Wifi )
                {
                    if( strID.isEmpty() )
                        strID = netIFT.hardwareAddress();
                    else
                    {
                        strID += QString( "|%1" ).arg( netIFT.hardwareAddress() );
                    }
                }
            }
        }
    }
#endif

    return strID;
}

static const QString _getFileFilter( int nType, QString& strFileType )
{
    QString strFilter;

    if( nType == JS_FILE_TYPE_CERT )
    {
        strFileType = QObject::tr("Cert Files");
        strFilter = QString("%1 (*.crt *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CRL )
    {
        strFileType = QObject::tr( "CRL Files" );
        strFilter = QString("%1 (*.crl *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CSR )
    {
        strFileType = QObject::tr( "CSR Files" );
        strFilter = QString("%1 (*.csr *.der *.req *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PRIKEY )
    {
        strFileType = QObject::tr("PrivateKey Files");
        strFilter = QString("%1 (*.key *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_DB )
    {
        strFileType = QObject::tr( "DB Files" );
        strFilter = QString( "%1 (*.db *.db3 *.xdb)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_DLL )
    {
#ifdef WIN32
        strFileType = QObject::tr( "DLL Files" );
        strFilter = QString( "%1 (*.dll);;SO Files (*.so)" ).arg( strFileType );
#else
        strFileType = QObject::tr( "SO Files" );
        strFilter = QString( "SO Files (*.so *.dylib)" ).arg( strFileType );
#endif
    }
    else if( nType == JS_FILE_TYPE_TXT )
    {
        strFileType = QObject::tr("Text Files");
        strFilter = QString("%1 (*.txt *.log)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_BER )
    {
        strFileType = QObject::tr("BER Files");
        strFilter = QString("%1 (*.ber *.der *.cer *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_CFG )
    {
        strFileType = QObject::tr("Config Files");
        strFilter = QString("%1 (*.cfg *.ini)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PFX )
    {
        strFileType = QObject::tr("PFX Files");
        strFilter = QString("%1 (*.pfx *.p12 *.pem)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_BIN )
    {
        strFileType = QObject::tr("Binary Files");
        strFilter = QString("%1 (*.bin *.ber *.der)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PKCS7 )
    {
        strFileType = QObject::tr("PKCS7 Files");
        strFilter = QString("%1 (*.p7b *.pkcs7 *.der *.pem)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PKCS8 )
    {
        strFileType = QObject::tr("PKCS8 Files");
        strFilter = QString("%1 (*.pk8 *.p8 *.der *.pem)").arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_JSON )
    {
        strFileType = QObject::tr("JSON Files");
        strFilter = QString("%1 (*.json *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_LCN )
    {
        strFileType = QObject::tr("License Files");
        strFilter = QString( "%1 (*.lcn *.txt)" ).arg( strFileType );
    }
    else if( nType == JS_FILE_TYPE_PRIKEY_PKCS8_PFX )
    {
        strFileType = QObject::tr("PrivateKey Files");
        strFilter = QString("%1 (*.key *.der *.pem)").arg( strFileType );

        strFilter += ";;";
        strFileType = QObject::tr("PKCS8 Files");
        strFilter += QString("%1 (*.pk8 *.p8)" ).arg( strFileType );

        strFilter += ";;";
        strFileType = QObject::tr("PFX Files");
        strFilter += QString("%1 (*.pfx *.p12 *.pem)" ).arg( strFileType );
    }

    if( strFilter.length() > 0 ) strFilter += ";;";
    strFilter += QObject::tr( "All Files (*.*)" );

    return strFilter;
}

static const QString _getFileExt( int nType )
{
    QString strExt;

    if( nType == JS_FILE_TYPE_CERT )
    {
        strExt = "crt";
    }
    else if( nType == JS_FILE_TYPE_CRL )
    {
        strExt = "crl";
    }
    else if( nType == JS_FILE_TYPE_CSR )
    {
        strExt = "csr";
    }
    else if( nType == JS_FILE_TYPE_PRIKEY )
    {
        strExt = "key";
    }
    else if( nType == JS_FILE_TYPE_PKCS8 )
    {
        strExt = "pk8";
    }
    else if( nType == JS_FILE_TYPE_TXT )
    {
        strExt = "txt";
    }
    else if( nType == JS_FILE_TYPE_BER )
    {
        strExt = "ber";
    }
    else if( nType == JS_FILE_TYPE_CFG )
    {
        strExt = "cfg";
    }
    else if( nType == JS_FILE_TYPE_PFX )
    {
        strExt = "pfx";
    }
    else if( nType == JS_FILE_TYPE_BIN )
    {
        strExt = "bin";
    }
    else if( nType == JS_FILE_TYPE_PKCS7 )
    {
        strExt = "p7b";
    }
    else if( nType == JS_FILE_TYPE_JSON )
    {
        strExt = "json";
    }
    else if( nType == JS_FILE_TYPE_LCN )
    {
        strExt = "lcn";
    }
    else
    {
        strExt = "pem";
    }

    return strExt;
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

    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                    QObject::tr( "Open %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    return fileName;
};

QString findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;


    QString fileName = QFileDialog::getOpenFileName( parent,
                                                    QObject::tr( "Open %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &strSelected,
                                                    options );

    return fileName;
};


QString findSaveFile( QWidget *parent, int nType, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

    //    QString strPath = QDir::currentPath();

    QString strFileType;
    QString strFilter = _getFileFilter( nType, strFileType );
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    if( fileName.length() > 0 )
    {
        QStringList nameVal = fileName.split( "." );
        if( nameVal.size() < 2 )
            fileName = QString( "%1.%2" ).arg( fileName ).arg( _getFileExt( nType ) );
    }

    return fileName;
};

QString findSaveFile( QWidget *parent, const QString strFilter, const QString strPath )
{
    QString strCurPath;

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    if( strPath.length() <= 0 )
        strCurPath = QDir::currentPath();
    else
        strCurPath = strPath;

    //    QString strPath = QDir::currentPath();

    QString strFileType;
    QString selectedFilter;

    QString fileName = QFileDialog::getSaveFileName( parent,
                                                    QObject::tr( "Save %1" ).arg( strFileType ),
                                                    strCurPath,
                                                    strFilter,
                                                    &selectedFilter,
                                                    options );

    return fileName;
}

QString findFolder( QWidget *parent, const QString strPath )
{
    QFileDialog::Options options;
    options |= QFileDialog::ShowDirsOnly;
    options |= QFileDialog::DontResolveSymlinks;


    QString folderName = QFileDialog::getExistingDirectory(
        parent, QObject::tr("Open Directory"), strPath, options);

    return folderName;
}


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

    if( strSN == JS_PKI_ExtNameKeyUsage )
    {
        ret = _setKeyUsage( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLNum )
    {
        ret = _setCRLNum( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePolicy )
    {
        ret = _setCertPolicy( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSKI )
    {
        ret = _setSKI( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAKI )
    {
        ret = _setAKI( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameEKU )
    {
        ret = _setEKU( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLDP )
    {
        ret = _setCRLDP( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameBC )
    {
        ret = _setBC( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePC )
    {
        ret = _setPC( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAIA )
    {
        ret = _setAIA( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameIDP )
    {
        ret = _setIDP( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSAN || strSN == JS_PKI_ExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _setAltName( &binExt, nNid, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePM )
    {
        ret = _setPM( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameNC )
    {
        ret = _setNC( &binExt, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLReason )
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

    if( strSN == JS_PKI_ExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSKI )
    {
        ret = _getSKI( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAKI )
    {
        ret = _getAKI( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameEKU )
    {
        ret = _getEKU( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameBC )
    {
        ret = _getBC( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePC )
    {
        ret = _getPC( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAIA )
    {
        ret = _getAIA( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameIDP )
    {
        ret = _getIDP( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSAN || strSN == JS_PKI_ExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePM )
    {
        ret = _getPM( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameNC )
    {
        ret = _getNC( &binExt, false, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLReason )
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

    if( strSN == JS_PKI_ExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSKI )
    {
        ret = _getSKI( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAKI )
    {
        ret = _getAKI( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameEKU )
    {
        ret = _getEKU( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameBC )
    {
        ret = _getBC( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePC )
    {
        ret = _getPC( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameAIA )
    {
        ret = _getAIA( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameIDP )
    {
        ret = _getIDP( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameSAN || strSN == JS_PKI_ExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePM )
    {
        ret = _getPM( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameNC )
    {
        ret = _getNC( &binExt, true, strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, true, strVal );
    }
    else
    {
        strVal = pExtInfo->pValue;
    }

    JS_BIN_reset( &binExt );
}

const QString getExtValue( const QString strName, const QString strHexValue, bool bShow )
{
    int ret = 0;
    QString strVal;

    BIN     binExt = {0,0};

    JS_BIN_decodeHex( strHexValue.toStdString().c_str(), &binExt );

    if( strName == JS_PKI_ExtNameKeyUsage )
    {
        ret = _getKeyUsage( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameCRLNum )
    {
        ret = _getCRLNum( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNamePolicy )
    {
        ret = _getCertPolicy( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameSKI )
    {
        ret = _getSKI( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameAKI )
    {
        ret = _getAKI( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameEKU )
    {
        ret = _getEKU( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameCRLDP )
    {
        ret = _getCRLDP( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameBC )
    {
        ret = _getBC( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNamePC )
    {
        ret = _getPC( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameAIA )
    {
        ret = _getAIA( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameIDP )
    {
        ret = _getIDP( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameSAN || strName == JS_PKI_ExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strName.toStdString().c_str() );
        ret = _getAltName( &binExt, nNid, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNamePM )
    {
        ret = _getPM( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameNC )
    {
        ret = _getNC( &binExt, bShow, strVal );
    }
    else if( strName == JS_PKI_ExtNameCRLReason )
    {
        ret = _getCRLReason( &binExt, bShow, strVal );
    }
    else
    {
        strVal = strHexValue;
    }

    JS_BIN_reset( &binExt );
    return strVal;
}

const QString getProfileExtInfoValue( const QString strSN, const QString& strVal )
{
    QString strShowVal;

    if( strSN == JS_PKI_ExtNameKeyUsage )
    {
        strShowVal = _getKeyUsageProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLNum )
    {
        strShowVal = _getCRLNumProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNamePolicy )
    {
        strShowVal = _getCertPolicyProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameSKI )
    {
        strShowVal = _getSKIProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameAKI )
    {
        strShowVal = _getAKIProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameEKU )
    {
        strShowVal = _getEKUProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLDP )
    {
        strShowVal = _getCRLDPProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameBC )
    {
        strShowVal = _getBCProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNamePC )
    {
        strShowVal = _getPCProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameAIA )
    {
        strShowVal = _getAIAProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameIDP )
    {
        strShowVal = _getIDPProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameSAN || strSN == JS_PKI_ExtNameIAN )
    {
        int nNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );
        strShowVal = _getAltNameProfile( nNid, strVal );
    }
    else if( strSN == JS_PKI_ExtNamePM )
    {
        strShowVal = _getPMProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameNC )
    {
        strShowVal = _getNCProfile( strVal );
    }
    else if( strSN == JS_PKI_ExtNameCRLReason )
    {
        strShowVal = _getCRLReasonProfile( strVal );
    }
    else
    {
        strShowVal = strVal;
    }

    return strShowVal;
}

CK_SESSION_HANDLE getP11Session( void *pP11CTX, int nSlotID, const QString strPIN )
{
    int ret = 0;

    QString strPass;
    JP11_CTX    *pCTX = (JP11_CTX *)pP11CTX;

    int nFlags = 0;
    BIN binPIN = {0,0};

    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    if( pCTX == NULL ) return -1;


    if( strPIN == nullptr || strPIN.length() < 1 )
    {
        PinDlg pinDlg;
        ret = pinDlg.exec();
        if( ret == QDialog::Accepted )
            strPass = pinDlg.getPinText();
    }
    else
    {
        strPass = strPIN;
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

    getBINFromString( &binPIN, DATA_STRING, strPass );

    ret = JS_PKCS11_Login( pCTX, nUserType, binPIN.pVal, binPIN.nLen );
    JS_BIN_reset( &binPIN );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    return pCTX->hSession;
}

CK_OBJECT_HANDLE getHandleHSM( JP11_CTX *pCTX, CK_OBJECT_CLASS objClass, const BIN *pID )
{
    int rv;

    CK_ATTRIBUTE sTemplate[2];
    long uCount = 0;

    CK_OBJECT_HANDLE hObjects = 0;
    CK_ULONG uObjCnt = 0;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    if( pID )
    {
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = pID->pVal;
        sTemplate[uCount].ulValueLen = pID->nLen;
        uCount++;
    }

    rv = JS_PKCS11_FindObjectsInit( pCTX, sTemplate, uCount );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjects( pCTX, &hObjects, 1, &uObjCnt );
    if( rv != CKR_OK ) goto end;

    rv = JS_PKCS11_FindObjectsFinal( pCTX );
    if( rv != CKR_OK ) goto end;

end :

    return hObjects;
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

    JS_SSL_initConnect( pCTX, strHost.toStdString().c_str(), strPort.toInt(), &pSSL );
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

int genKeyPairWithP11( JP11_CTX *pCTX, QString strName, QString strAlg, QString strParam, int nExponent, BIN *pPri, BIN *pPub )
{
    JP11_CTX   *pP11CTX = NULL;

    int rv;

    pP11CTX = pCTX;

    CK_ATTRIBUTE sPubTemplate[20];
    CK_ULONG uPubCount = 0;
    CK_ATTRIBUTE sPriTemplate[20];
    CK_ULONG uPriCount = 0;
    CK_MECHANISM sMech;
    CK_KEY_TYPE keyType;

    CK_OBJECT_HANDLE uPubObj = 0;
    CK_OBJECT_HANDLE uPriObj = 0;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;

    BIN binLabel = {0,0};
    JS_BIN_set( &binLabel, (unsigned char *)strName.toStdString().c_str(), strName.toUtf8().length() );


    BIN binPubExponent = {0,0};
    BIN binGroup = {0,0};
    CK_ULONG	uModBitLen = 0;

    BIN binVal = {0,0};
    BIN binHash = {0,0};

    BIN binP = {0,0};
    BIN binG = {0,0};
    BIN binQ = {0,0};

    BIN binKey = {0,0};
    BIN binPubX = {0,0};
    BIN binPubY = {0,0};

    char sCurveOID[128];

    memset( &sMech, 0x00, sizeof(sMech) );
    memset( sCurveOID, 0x00, sizeof(sCurveOID));

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
    else if( strAlg == kMechPKCS11_DSA )
    {
        sMech.mechanism = CKM_DSA_KEY_PAIR_GEN;
        keyType = CKK_DSA;
    }
    else if( strAlg == kMechPKCS11_EdDSA )
    {
        sMech.mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN;
        keyType = CKK_EC_EDWARDS;
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
        strDecimal = QString( "%1" ).arg( nExponent );
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
        JS_PKI_getOIDFromSN( strParam.toStdString().c_str(), sCurveOID );
        JS_PKI_getOIDFromString( sCurveOID, &binGroup );

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binGroup.pVal;
        sPubTemplate[uPubCount].ulValueLen = binGroup.nLen;
        uPubCount++;
    }
    else if( keyType == CKK_EC_EDWARDS )
    {
        if( strParam == kParamEd25519 )
        {
            sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
            sPubTemplate[uPubCount].pValue = kOID_X25519;
            sPubTemplate[uPubCount].ulValueLen = sizeof(kOID_X25519);
            uPubCount++;
        }
        else if( strParam == kParamEd448 )
        {
            sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
            sPubTemplate[uPubCount].pValue = kOID_X448;
            sPubTemplate[uPubCount].ulValueLen = sizeof(kOID_X448);
            uPubCount++;
        }
    }
    else if( keyType == CKK_DSA )
    {
        uModBitLen = strParam.toInt();
        JS_PKI_DSA_GenParamValue( uModBitLen, &binP, &binQ, &binG );

        sPubTemplate[uPubCount].type = CKA_PRIME;
        sPubTemplate[uPubCount].pValue = binP.pVal;
        sPubTemplate[uPubCount].ulValueLen = binP.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_SUBPRIME;
        sPubTemplate[uPubCount].pValue = binQ.pVal;
        sPubTemplate[uPubCount].ulValueLen = binQ.nLen;
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_BASE;
        sPubTemplate[uPubCount].pValue = binG.pVal;
        sPubTemplate[uPubCount].ulValueLen = binG.nLen;
        uPubCount++;
    }

    sPubTemplate[uPubCount].type = CKA_TOKEN;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

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

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        JS_BIN_set( &binKey, binVal.pVal + 3, binVal.nLen - 3 ); // 04+Len(1byte)+04 건너팀
        JS_BIN_set( &binPubX, &binKey.pVal[0], binKey.nLen/2 );
        JS_BIN_set( &binPubY, &binKey.pVal[binKey.nLen/2], binKey.nLen/2 );


        JS_BIN_encodeHex( &binPubX, &pPubX );
        JS_BIN_encodeHex( &binPubY, &pPubY );

        JS_PKI_setECKeyVal( &ecKey, sCurveOID, pPubX, pPubY, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub );

        if( pPubX ) JS_free( pPubX );
        if( pPubY ) JS_free( pPubY );
        JS_BIN_reset( &binKey );
        JS_PKI_resetECKeyVal( &ecKey );
    }
    else if( keyType == CKK_EC_EDWARDS )
    {
        BIN binVal = {0,0};
        BIN binXY = {0,0};

        JRawKeyVal sRawKey;
        char *pPubHex = NULL;

        memset( &sRawKey, 0x00, sizeof(sRawKey));

        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_EC_POINT, &binVal );
        if( rv != 0 ) goto end;

        JS_BIN_set( &binXY, &binVal.pVal[2], binVal.nLen - 2);

        JS_BIN_encodeHex( &binXY, &pPubHex );
        JS_PKI_setRawKeyVal( &sRawKey, pPubHex, NULL, strParam.toStdString().c_str() );
        rv = JS_PKI_encodeRawPublicKey( &sRawKey, pPub );

        JS_PKI_resetRawKeyVal( &sRawKey );
        if( pPubHex ) JS_free( pPubHex );
        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binXY );
    }
    else if( keyType == CKK_DSA )
    {
        char *pHexG = NULL;
        char *pHexP = NULL;
        char *pHexQ = NULL;
        char *pHexPub = NULL;

        JDSAKeyVal sDSAKey;
        memset( &sDSAKey, 0x00, sizeof(sDSAKey));

        rv = JS_PKCS11_GetAttributeValue2( pP11CTX, uPubObj, CKA_VALUE, &binVal );
        if( rv != 0 ) goto end;

        JS_BIN_encodeHex( &binP, &pHexP );
        JS_BIN_encodeHex( &binQ, &pHexQ );
        JS_BIN_encodeHex( &binG, &pHexG );
        JS_BIN_encodeHex( &binVal, &pHexPub );

        JS_PKI_setDSAKeyVal( &sDSAKey, pHexG, pHexP, pHexQ, pHexPub, NULL );
        JS_PKI_encodeDSAPublicKey( &sDSAKey, pPub );

        if( pHexG ) JS_free( pHexG );
        if( pHexP ) JS_free( pHexP );
        if( pHexQ ) JS_free( pHexQ );
        if( pHexPub ) JS_free( pHexPub );

        JS_PKI_resetDSAKeyVal( &sDSAKey );
    }

    JS_PKI_getKeyIdentifier( pPub, &binHash );
    JS_BIN_copy( pPri, &binHash );

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uPriObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

    rv = JS_PKCS11_SetAttributeValue2( pP11CTX, uPubObj, CKA_ID, &binHash );
    if( rv != 0 ) goto end;

end :
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binPubExponent );
    JS_BIN_reset( &binGroup );
    JS_BIN_reset( &binVal );
    JS_BIN_reset( &binHash );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );

    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binPubX );
    JS_BIN_reset( &binPubY );

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
    ret = JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
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
    ret = JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
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
    ret = JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
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
    ret = JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
    ret = JS_KMS_decodeGetRsp( &binRsp, &nType, &binData );

    if( nAlg == JS_PKI_KEY_TYPE_RSA )
    {
        JS_BIN_copy( pPub, &binData );
    }
    else if( nAlg == JS_PKI_KEY_TYPE_ECC )
    {
        char *pPubX = NULL;
        char *pPubY = NULL;

        char sOID[128];

        JECKeyVal   ecKey;
        memset( &ecKey, 0x00, sizeof(ecKey));

        memset( sOID, 0x00, sizeof(sOID));

        JS_PKI_getOIDFromSN( "prime256v1", sOID );

        BIN binKey = {0,0};
        BIN binPubX = {0,0};
        BIN binPubY = {0,0};

        JS_BIN_set( &binKey, binData.pVal + 1, binData.nLen - 1 );
        JS_BIN_set( &binPubX, &binKey.pVal[0], binKey.nLen/2);
        JS_BIN_set( &binPubY, &binKey.pVal[binKey.nLen/2], binKey.nLen/2 );

        JS_BIN_encodeHex( &binPubX, &pPubX );
        JS_BIN_encodeHex( &binPubY, &pPubY );


        JS_PKI_setECKeyVal( &ecKey, sOID, pPubX, pPubY, NULL );
        JS_PKI_encodeECPublicKey( &ecKey, pPub );

        if( pPubX ) JS_free( pPubX );
        if( pPubY ) JS_free( pPubY );

        JS_BIN_reset( &binKey );
        JS_BIN_reset( &binPubX );
        JS_BIN_reset( &binPubY );
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

int createRSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strModulus = pRsaKeyVal->pN;
    BIN binModulus = {0,0};

    if( !strModulus.isEmpty() )
    {
        JS_BIN_decodeHex( strModulus.toStdString().c_str(), &binModulus );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModulus.pVal;
        sTemplate[uCount].ulValueLen = binModulus.nLen;
        uCount++;
    }

    QString strExponent = pRsaKeyVal->pE;
    BIN binExponent = {0,0};

    if( !strExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent.toStdString().c_str(), &binExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binExponent.pVal;
        sTemplate[uCount].ulValueLen = binExponent.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binModulus );
    JS_BIN_reset( &binExponent );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create RSA public key(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
}

int createRSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRSAKeyVal *pRsaKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;


    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strModules = pRsaKeyVal->pN;
    BIN binModules = {0,0};

    if( !strModules.isEmpty() )
    {
        JS_BIN_decodeHex( strModules.toStdString().c_str(), &binModules );
        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binModules.pVal;
        sTemplate[uCount].ulValueLen = binModules.nLen;
        uCount++;
    }

    QString strPublicExponent = pRsaKeyVal->pE;
    BIN binPublicExponent = {0,0};

    if( !strPublicExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strPublicExponent.toStdString().c_str(), &binPublicExponent );
        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binPublicExponent.pVal;
        sTemplate[uCount].ulValueLen = binPublicExponent.nLen;
        uCount++;
    }

    QString strPrivateExponent = pRsaKeyVal->pD;
    BIN binPrivateExponent = {0,0};

    if( !strPrivateExponent.isEmpty() )
    {
        JS_BIN_decodeHex( strPrivateExponent.toStdString().c_str(), &binPrivateExponent );
        sTemplate[uCount].type = CKA_PRIVATE_EXPONENT;
        sTemplate[uCount].pValue = binPrivateExponent.pVal;
        sTemplate[uCount].ulValueLen = binPrivateExponent.nLen;
        uCount++;
    }

    QString strPrime1 = pRsaKeyVal->pP;
    BIN binPrime1 = {0,0};

    if( !strPrime1.isEmpty() )
    {
        JS_BIN_decodeHex( strPrime1.toStdString().c_str(), &binPrime1 );
        sTemplate[uCount].type = CKA_PRIME_1;
        sTemplate[uCount].pValue = binPrime1.pVal;
        sTemplate[uCount].ulValueLen = binPrime1.nLen;
        uCount++;
    }

    QString strPrime2 = pRsaKeyVal->pQ;
    BIN binPrime2 = {0,0};

    if( !strPrime2.isEmpty() )
    {
        JS_BIN_decodeHex( strPrime2.toStdString().c_str(), &binPrime2 );
        sTemplate[uCount].type = CKA_PRIME_2;
        sTemplate[uCount].pValue = binPrime2.pVal;
        sTemplate[uCount].ulValueLen = binPrime2.nLen;
        uCount++;
    }

    QString strExponent1 = pRsaKeyVal->pDMP1;
    BIN binExponent1 = {0,0};

    if( !strExponent1.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent1.toStdString().c_str(), &binExponent1 );
        sTemplate[uCount].type = CKA_EXPONENT_1;
        sTemplate[uCount].pValue = binExponent1.pVal;
        sTemplate[uCount].ulValueLen = binExponent1.nLen;
        uCount++;
    }

    QString strExponent2 = pRsaKeyVal->pDMQ1;
    BIN binExponent2 = {0,0};

    if( !strExponent2.isEmpty() )
    {
        JS_BIN_decodeHex( strExponent2.toStdString().c_str(), &binExponent2 );
        sTemplate[uCount].type = CKA_EXPONENT_2;
        sTemplate[uCount].pValue = binExponent2.pVal;
        sTemplate[uCount].ulValueLen = binExponent2.nLen;
        uCount++;
    }

    QString strCoefficient = pRsaKeyVal->pIQMP;
    BIN binCoefficient = {0,0};

    if( !strCoefficient.isEmpty() )
    {
        JS_BIN_decodeHex( strCoefficient.toStdString().c_str(), &binCoefficient );
        sTemplate[uCount].type = CKA_COEFFICIENT;
        sTemplate[uCount].pValue = binCoefficient.pVal;
        sTemplate[uCount].ulValueLen = binCoefficient.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length());
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binModules );
    JS_BIN_reset( &binPublicExponent );
    JS_BIN_reset( &binPrivateExponent );
    JS_BIN_reset( &binPrime1 );
    JS_BIN_reset( &binPrime2 );
    JS_BIN_reset( &binExponent1 );
    JS_BIN_reset( &binExponent2 );
    JS_BIN_reset( &binCoefficient );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create RSA private key(%s)\n", JS_PKCS11_GetErrorMsg(rv) );
        return rv;
    }

    return rv;
}

int createECPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pEcKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pEcKeyVal->pCurveOID;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strECPoints = pEcKeyVal->pPubX;
    strECPoints += pEcKeyVal->pPubY;
    BIN binECPoints = {0,0};

    if( !strECPoints.isEmpty() )
    {
        JS_BIN_decodeHex( strECPoints.toStdString().c_str(), &binECPoints );
        sTemplate[uCount].type = CKA_EC_POINT;
        sTemplate[uCount].pValue = binECPoints.pVal;
        sTemplate[uCount].ulValueLen = binECPoints.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binECPoints );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create EC public key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createECPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JECKeyVal *pECKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pECKeyVal->pCurveOID;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strValue = pECKeyVal->pPrivate;
    BIN binValue = {0,0};

    if( !strValue.isEmpty() )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binValue);
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binValue.pVal;
        sTemplate[uCount].ulValueLen = binValue.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );


    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create EC private key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createEDPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC_EDWARDS;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pRawKeyVal->pName;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strECPoints = pRawKeyVal->pPub;
    BIN binECPoints = {0,0};

    if( !strECPoints.isEmpty() )
    {
        JS_BIN_decodeHex( strECPoints.toStdString().c_str(), &binECPoints );
        sTemplate[uCount].type = CKA_EC_POINT;
        sTemplate[uCount].pValue = binECPoints.pVal;
        sTemplate[uCount].ulValueLen = binECPoints.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binECPoints );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create EC public key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createEDPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JRawKeyVal *pRawKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC_EDWARDS;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strECParams = pRawKeyVal->pName;
    BIN binECParams = {0,0};

    if( !strECParams.isEmpty() )
    {
        JS_PKI_getOIDFromString( strECParams.toStdString().c_str(), &binECParams );
        sTemplate[uCount].type = CKA_EC_PARAMS;
        sTemplate[uCount].pValue = binECParams.pVal;
        sTemplate[uCount].ulValueLen = binECParams.nLen;
        uCount++;
    }

    QString strValue = pRawKeyVal->pPri;
    BIN binValue = {0,0};

    if( !strValue.isEmpty() )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binValue);
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binValue.pVal;
        sTemplate[uCount].ulValueLen = binValue.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );
        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binECParams );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create EC private key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}


int createDSAPublicKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL    bTrue = CK_TRUE;
    CK_BBOOL    bFalse = CK_FALSE;
    CK_OBJECT_HANDLE    hObject = 0;

    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strP = pDSAKeyVal->pP;
    BIN binP = {0,0};

    if( !strP.isEmpty() )
    {
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        sTemplate[uCount].type = CKA_PRIME;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;
    }

    QString strQ = pDSAKeyVal->pQ;
    BIN binQ = {0,0};

    if( !strQ.isEmpty() )
    {
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
        sTemplate[uCount].type = CKA_SUBPRIME;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;
    }

    QString strG = pDSAKeyVal->pG;
    BIN binG = {0,0};

    if( !strG.isEmpty() )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        sTemplate[uCount].type = CKA_BASE;
        sTemplate[uCount].pValue = binG.pVal;
        sTemplate[uCount].ulValueLen = binG.nLen;
        uCount++;
    }

    QString strPublic = pDSAKeyVal->pPublic;
    BIN binPublic = {0,0};

    if( !strPublic.isEmpty() )
    {
        JS_BIN_decodeHex( strPublic.toStdString().c_str(), &binPublic );
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binPublic.pVal;
        sTemplate[uCount].ulValueLen = binPublic.nLen;
        uCount++;
    }


    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binPublic );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf( stderr, "fail to create DSA public key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int createDSAPrivateKeyP11( JP11_CTX *pCTX, const QString& strLabel, const BIN *pID, const JDSAKeyVal *pDSAKeyVal )
{
    int rv = -1;

    CK_ATTRIBUTE sTemplate[20];
    long uCount = 0;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_KEY_TYPE;
    sTemplate[uCount].pValue = &keyType;
    sTemplate[uCount].ulValueLen = sizeof(keyType);
    uCount++;

    QString strP = pDSAKeyVal->pP;
    BIN binP = {0,0};

    if( !strP.isEmpty() )
    {
        JS_BIN_decodeHex( strP.toStdString().c_str(), &binP );
        sTemplate[uCount].type = CKA_PRIME;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;
    }

    QString strQ = pDSAKeyVal->pQ;
    BIN binQ = {0,0};

    if( !strQ.isEmpty() )
    {
        JS_BIN_decodeHex( strQ.toStdString().c_str(), &binQ );
        sTemplate[uCount].type = CKA_SUBPRIME;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;
    }

    QString strG = pDSAKeyVal->pG;
    BIN binG = {0,0};

    if( !strG.isEmpty() )
    {
        JS_BIN_decodeHex( strG.toStdString().c_str(), &binG );
        sTemplate[uCount].type = CKA_BASE;
        sTemplate[uCount].pValue = binG.pVal;
        sTemplate[uCount].ulValueLen = binG.nLen;
        uCount++;
    }

    QString strValue = pDSAKeyVal->pPrivate;
    BIN binValue = {0,0};

    if( !strValue.isEmpty() )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), &binValue);
        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binValue.pVal;
        sTemplate[uCount].ulValueLen = binValue.nLen;
        uCount++;
    }

    BIN binLabel = {0,0};

    if( !strLabel.isEmpty() )
    {
        JS_BIN_set( &binLabel, (unsigned char *)strLabel.toStdString().c_str(), strLabel.toUtf8().length() );
        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = binLabel.pVal;
        sTemplate[uCount].ulValueLen = binLabel.nLen;
        uCount++;
    }

    BIN binID = {0,0};

    if( pID )
    {
        JS_BIN_copy( &binID, pID );

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = binID.pVal;
        sTemplate[uCount].ulValueLen = binID.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_PRIVATE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SENSITIVE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    sTemplate[uCount].type = CKA_SIGN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof( bTrue );
    uCount++;

    CK_OBJECT_HANDLE hObject = 0;

    rv = JS_PKCS11_CreateObject( pCTX, sTemplate, uCount, &hObject );

    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binG );
    JS_BIN_reset( &binValue );
    JS_BIN_reset( &binLabel );
    JS_BIN_reset( &binID );

    if( rv != CKR_OK )
    {
        fprintf(stderr, "fail to create DSA private key(%s)\n", JS_PKCS11_GetErrorMsg(rv));
        return rv;
    }

    return rv;
}

int addAudit( DBMgr *dbMgr, int nKind, int nOP, QString strInfo )
{
    int ret = 0;
    AuditRec auditRec;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHMAC = {0,0};

    char *pHex = NULL;

    if( dbMgr == NULL ) return -1;

    int nSeq = dbMgr->getNextVal( "TB_AUDIT" );
//    nSeq++;

    auditRec.setSeq( nSeq );
    auditRec.setKind( nKind );
    auditRec.setOperation( nOP );
    auditRec.setInfo( strInfo );
    auditRec.setRegTime( time(NULL) );
    auditRec.setUserName( "admin" );

    JS_GEN_getHMACKey( &binKey );

    QString strSrc = QString( "%1_%2_%3_%4_%5_%6" )
            .arg( nSeq)
            .arg( nKind )
            .arg( nOP )
            .arg( strInfo )
            .arg( auditRec.getRegTime() )
            .arg( auditRec.getUserName() );

    JS_BIN_set( &binSrc, (unsigned char *)strSrc.toStdString().c_str(), strSrc.length() );

    ret = JS_PKI_genHMAC( "SHA256", &binSrc, &binKey, &binHMAC );
    if( ret != 0 ) goto end;

    JS_BIN_encodeHex( &binHMAC, &pHex );
    if( pHex )
    {
        auditRec.setMAC( pHex );
        dbMgr->addAuditRec( auditRec );
    }

end :
    if( pHex ) JS_free( pHex );
    JS_BIN_reset( &binHMAC );
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binKey );

    return ret;
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

    JS_BIN_set( &binSrc, (unsigned char *)strSrc.toStdString().c_str(), strSrc.length() );

    ret = JS_PKI_genHMAC( "SHA256", &binSrc, &binKey, &binHMAC );
    if( ret != 0 ) goto end;

    JS_BIN_decodeHex( audit.getMAC().toStdString().c_str(), &binRecHMAC );

    ret = JS_BIN_cmp( &binHMAC, &binRecHMAC );

end :
    JS_BIN_reset( &binHMAC );
    JS_BIN_reset( &binRecHMAC );
    JS_BIN_reset( &binSrc );

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
    certRec.setIssuerNum( kImportNum );
    certRec.setSignAlg( sCertInfo.pSignAlgorithm );
    nRet = dbMgr->addCertRec( certRec );

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

    nSeq = dbMgr->getNextVal( "TB_CRL" );

    JS_BIN_encodeHex( pCRL, &pHex );

    crlRec.setNum( nSeq );
    crlRec.setRegTime( time(NULL));
    crlRec.setIssuerNum( -2 );
    crlRec.setSignAlg( sCRLInfo.pSignAlgorithm );
    crlRec.setCRL( pHex );

    nRet = dbMgr->addCRLRec( crlRec );

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

    seq = dbMgr->getNextVal( "TB_REQ" );
    //seq++;

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
    dateTime.setSecsSinceEpoch( tTime );

    if( tTime < 0 ) return "NA";

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

QString getHexString( const BIN *pBin )
{
    char *pHex = NULL;

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    JS_BIN_encodeHex( pBin, &pHex );

    QString strHex = pHex;
    if(pHex) JS_free( pHex );

    return strHex;
}

QString getHexString( unsigned char *pData, int nDataLen )
{
    BIN binData = {0,0};
    char *pHex = NULL;
    JS_BIN_set( &binData, pData, nDataLen );
    JS_BIN_encodeHex( &binData, &pHex );

    QString strHex = pHex;

    JS_BIN_reset( &binData );
    if(pHex) JS_free( pHex );

    return strHex;
}

const QString getHexStringArea( unsigned char *pData, int nDataLen, int nWidth  )
{
    QString strMsg = getHexString( pData, nDataLen );

    return getHexStringArea( strMsg, nWidth );
}

const QString getHexStringArea( const BIN *pData, int nWidth )
{
    QString strMsg = getHexString( pData );

    return getHexStringArea( strMsg, nWidth );
}

const QString getHexStringArea( const QString strMsg, int nWidth )
{
    int nBlock = 0;
    int nPos = 0;
    QString strAreaMsg = nullptr;

    int nLen = strMsg.length();
    if( nWidth <= 0 ) return strMsg;

    while( nLen > 0 )
    {
        if( nLen >= nWidth )
            nBlock = nWidth;
        else
            nBlock = nLen;

        strAreaMsg += strMsg.mid( nPos, nBlock );

        nLen -= nBlock;
        nPos += nBlock;

        if( nLen > 0 ) strAreaMsg += "\n";
    }

    return strAreaMsg;
}

int getDataLen( int nType, const QString strData )
{
    int nLen = 0;
    if( strData.isEmpty() ) return 0;

    QString strMsg = strData;

    if( nType == DATA_HEX )
    {
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }
    else if( nType == DATA_BASE64 )
    {
        strMsg.remove( QRegularExpression( "-----BEGIN [^-]+-----") );
        strMsg.remove( QRegularExpression("-----END [^-]+-----") );
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        if( isHex( strMsg ) == false ) return -1;
        if( strMsg.length() % 2 ) return -2;

        nLen = strMsg.length() / 2;
    }
    else if( nType == DATA_BASE64 )
    {
        if( isBase64( strMsg ) == false ) return -1;

        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );
    }
    else if( nType == DATA_URL )
    {
        if( isURLEncode( strMsg ) == false ) return -1;

        char *pURL = NULL;
        JS_BIN_decodeURL( strMsg.toStdString().c_str(), &pURL );
        if( pURL )
        {
            nLen = strlen( pURL );
            JS_free( pURL );
        }
    }
    else
    {
        nLen = strData.toUtf8().length();
    }

    return nLen;
}

int getDataLen( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;
    else if( strLower == "url" )
        nType = DATA_URL;

    return getDataLen( nType, strData );
}


const QString getDataLenString( int nType, const QString strData )
{
    int nLen = 0;
    if( strData.isEmpty() ) return 0;

    QString strMsg = strData;
    QString strLen;

    if( nType == DATA_HEX )
    {
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }
    else if( nType == DATA_BASE64 )
    {
        strMsg.remove( QRegularExpression( "-----BEGIN [^-]+-----") );
        strMsg.remove( QRegularExpression("-----END [^-]+-----") );
        strMsg.remove( QRegularExpression("[\t\r\n\\s]") );
    }

    if( nType == DATA_HEX )
    {
        if( isHex( strMsg ) == false )
        {
            strLen = QString( "-1" );
            return strLen;
        }

        nLen = strMsg.length() / 2;

        if( strMsg.length() % 2 )
        {
            nLen++;
            strLen = QString( "_%1" ).arg( nLen );
        }
        else
        {
            strLen = QString( "%1" ).arg( nLen );
        }
    }
    else if( nType == DATA_BASE64 )
    {
        if( isBase64( strMsg ) == false )
        {
            strLen = QString( "-1" );
            return strLen;
        }

        BIN bin = {0,0};
        JS_BIN_decodeBase64( strMsg.toStdString().c_str(), &bin );
        nLen = bin.nLen;
        JS_BIN_reset( &bin );

        strLen = QString( "%1" ).arg( nLen );
    }
    else if( nType == DATA_URL )
    {
        if( isURLEncode( strMsg ) == false )
        {
            strLen = QString( "-1" );
            return strLen;
        }

        char *pURL = NULL;
        JS_BIN_decodeURL( strMsg.toStdString().c_str(), &pURL );
        if( pURL )
        {
            nLen = strlen( pURL );
            JS_free( pURL );
        }

        strLen = QString( "%1" ).arg( nLen );
    }
    else
    {
        strLen = QString( "%1" ).arg( strMsg.toUtf8().length() );
    }


    return strLen;
}

const QString getDataLenString( const QString strType, const QString strData )
{
    int nType = DATA_STRING;

    QString strLower = strType.toLower();

    if( strLower == "hex" )
        nType = DATA_HEX;
    else if( strLower == "base64" )
        nType = DATA_BASE64;
    else if( strLower == "url" )
        nType = DATA_URL;

    return getDataLenString( nType, strData );
}

void getBINFromString( BIN *pBin, const QString& strType, const QString& strString )
{
    int nType = 0;

    if( strType.toUpper() == "HEX" )
        nType = DATA_HEX;
    else if( strType.toUpper() == "BASE64" )
        nType = DATA_BASE64;
    else if( strType.toUpper() == "URL" )
        nType = DATA_URL;
    else
        nType = DATA_STRING;

    getBINFromString( pBin, nType, strString );
}

void getBINFromString( BIN *pBin, int nType, const QString& strString )
{
    QString srcString = strString;

    if( pBin == NULL ) return;

    if( nType == DATA_HEX )
    {
        srcString.remove( QRegularExpression("[\t\r\n\\s]") );
        if( isHex( srcString ) == false ) return;

        JS_BIN_decodeHex( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_BASE64 )
    {
        srcString.remove( QRegularExpression( "-----BEGIN [^-]+-----") );
        srcString.remove( QRegularExpression("-----END [^-]+-----") );
        srcString.remove( QRegularExpression("[\t\r\n\\s]") );
        if( isBase64( srcString ) == false ) return;

        JS_BIN_decodeBase64( srcString.toStdString().c_str(), pBin );
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
        if( isURLEncode( srcString ) == false ) return;

        JS_BIN_decodeURL( srcString.toStdString().c_str(), &pStr );

        if( pStr )
        {
            JS_BIN_set( pBin, (unsigned char *)pStr, strlen(pStr));
            JS_free( pStr );
        }
    }
    else
    {
        JS_BIN_set( pBin, (unsigned char *)srcString.toStdString().c_str(), srcString.toUtf8().length() );
    }
}

QString getStringFromBIN( const BIN *pBin, const QString& strType, bool bSeenOnly )
{
    int nType = 0;

    if( strType.toUpper() == "HEX" )
        nType = DATA_HEX;
    else if( strType.toUpper() == "BASE64" )
        nType = DATA_BASE64;
    else if( strType.toUpper() == "URL" )
        nType = DATA_URL;
    else
        nType = DATA_STRING;

    return getStringFromBIN( pBin, nType, bSeenOnly );
}

static char _getch( unsigned char c )
{
    if( isprint(c) )
        return c;
    else {
        return '.';
    }
}

QString getStringFromBIN( const BIN *pBin, int nType, bool bSeenOnly )
{
    QString strOut;
    char *pOut = NULL;

    if( pBin == NULL || pBin->nLen <= 0 ) return "";

    if( nType == DATA_HEX )
    {
        JS_BIN_encodeHex( pBin, &pOut );
        strOut = pOut;
    }
    else if( nType == DATA_BASE64 )
    {
        JS_BIN_encodeBase64( pBin, &pOut );
        strOut = pOut;
    }
    else if( nType == DATA_URL )
    {
        char *pStr = NULL;
        JS_BIN_string( pBin, &pStr );
        JS_BIN_encodeURL( pStr, &pOut );
        strOut = pOut;
        if( pStr ) JS_free( pStr );
    }
    else
    {
        int i = 0;

        if( bSeenOnly )
        {
            if( pBin->nLen > 0 )
            {
                pOut = (char *)JS_malloc(pBin->nLen + 1);

                for( i=0; i < pBin->nLen; i++ )
                    pOut[i] = _getch( pBin->pVal[i] );

                pOut[i] = 0x00;
            }
        }
        else
        {
            JS_BIN_string( pBin, &pOut );
        }

        strOut = pOut;
    }

    if( pOut ) JS_free( pOut );
    return strOut;
}

const QString getPasswdHMAC( const QString &strPasswd )
{
    QString strHex;
    BIN binHMAC = {0,0};
    BIN binKey = {0,0};
    BIN binSrc = {0,0};

    JS_GEN_getHMACKey( &binKey );
    getBINFromString( &binSrc, DATA_STRING, strPasswd );
    JS_PKI_genHMAC( "SHA256", &binSrc, &binKey, &binHMAC );

    strHex = getHexString( &binHMAC );

    JS_BIN_reset( &binHMAC );
    JS_BIN_reset( &binKey );
    JS_BIN_reset( &binSrc );

    return strHex;
}

const QString getNameFromDN( const QString& strDN )
{
    if( strDN.length() < 1 ) return "";

    QString strBuf = strDN;

    strBuf.replace( " ", "" );
    QStringList partList = strBuf.split( "," );

    if( partList.size() < 1 ) return "";

    QString strFirst = partList.at(0);

    QStringList firstList = strFirst.split( "=" );
    if( firstList.size() <= 1 ) return strFirst;

    return firstList.at(1);
}

int getKeyType( const QString& strAlg, const QString& strParam )
{
    int nKeyType = -1;

    if( strAlg == kMechRSA || strAlg == kMechPKCS11_RSA || strAlg == kMechKMIP_RSA )
        nKeyType = JS_PKI_KEY_TYPE_RSA;
    else if( strAlg == kMechEC || strAlg == kMechPKCS11_EC || strAlg == kMechKMIP_EC )
        nKeyType = JS_PKI_KEY_TYPE_ECC;
    else if( strAlg == kMechDSA || strAlg == kMechPKCS11_DSA )
        nKeyType = JS_PKI_KEY_TYPE_DSA;
    else if( strAlg == kMechSM2 )
        nKeyType = JS_PKI_KEY_TYPE_SM2;
    else if( strAlg == kMechEdDSA )
    {
        if( strParam == kParamEd25519 )
            nKeyType = JS_PKI_KEY_TYPE_ED25519;
        else
            nKeyType = JS_PKI_KEY_TYPE_ED448;
    }

    return nKeyType;
}

const QString getProfileType( int nProfileType )
{
    QString strType;

    if( nProfileType == JS_PKI_PROFILE_TYPE_CERT )
        strType = "CertProfile";
    else if( nProfileType == JS_PKI_PROFILE_TYPE_CSR )
        strType = "CSRProfile";
    else if( nProfileType == JS_PKI_PROFILE_TYPE_CRL )
        strType = "CRLProfile";
    else
        strType = "Unknown";

    return strType;
}

const QString getExtUsage( int nExtUsage )
{
    QString strUsage;

    if( nExtUsage == JS_PKI_EXT_CERT_ONLY )
        strUsage = "CertOnly";
    else if( nExtUsage == JS_PKI_EXT_CSR_ONLY )
        strUsage = "CSROnly";
    else if( nExtUsage == JS_PKI_EXT_BOTH_CERT_FIRST )
        strUsage = "BothAndCertFirst";
    else if( nExtUsage == JS_PKI_EXT_BOTH_CSR_FIRST )
        strUsage = "BothAdnCSRFirst";
    else
        strUsage = "Unknown";

    return strUsage;
}

const QString getCRLDPFromInfo( const QString &strExtCRLDP )
{
    QString strCRLDP;
    QStringList strList = strExtCRLDP.split( "#" );

    if( strList.size() < 1 )
    {
        strCRLDP.clear();
        return strCRLDP;
    }
    else
    {
        QString strFirst = strList.at(0);
        QStringList strParts = strFirst.split( "$" );
        if( strParts.size() < 2 )
        {
            strCRLDP.clear();
            return strCRLDP;
        }

        strCRLDP = strParts.at(1);
        return strCRLDP;
    }
}

bool isInternalPrivate( const QString strKeyMech )
{
    if( strKeyMech == kMechRSA ) return true;
    if( strKeyMech == kMechEC ) return true;
    if( strKeyMech == kMechEdDSA  ) return true;
    if( strKeyMech == kMechDSA ) return true;
    if( strKeyMech == kMechSM2 ) return true;

    return false;
}

bool isPKCS11Private( const QString strKeyMech )
{
    if( strKeyMech == kMechPKCS11_RSA ) return true;
    if( strKeyMech == kMechPKCS11_EC ) return true;
    if( strKeyMech == kMechPKCS11_DSA ) return true;
    if( strKeyMech == kMechPKCS11_EdDSA ) return true;

    return false;
}

bool isKMIPPrivate( const QString strKeyMech )
{
    if( strKeyMech == kMechKMIP_RSA ) return true;
    if( strKeyMech == kMechKMIP_EC ) return true;

    return false;
}

bool isHex( const QString strHexString )
{
    return isValidNumFormat( strHexString, 16 );
}

bool isBase64( const QString strBase64String )
{
    QRegExp base64REX("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
    base64REX.setCaseSensitivity(Qt::CaseInsensitive );

    return base64REX.exactMatch( strBase64String );
}

bool isURLEncode( const QString strURLEncode )
{
    QRegExp urlEncodeREX("^(?:[^%]|%[0-9A-Fa-f]{2})+$");
    urlEncodeREX.setCaseSensitivity(Qt::CaseInsensitive );

    return urlEncodeREX.exactMatch( strURLEncode );
}

bool isValidNumFormat( const QString strInput, int nNumber )
{
    QRegExp strReg;

    if( nNumber == 2 )
    {
        strReg.setPattern( "[0-1]+");
    }
    else if( nNumber == 16 )
    {
        strReg.setPattern( "[0-9a-fA-F]+" );
    }
    else
    {
        strReg.setPattern( "[0-9]+" );
    }

    return strReg.exactMatch( strInput );
}

const QString dateString( time_t tTime )
{
    QDateTime dateTime = QDateTime::fromTime_t( tTime );
    return dateTime.toString( "yy-MM-dd HH:mm" );
}

void getPeriodString( long start, long end, QString& strStart, QString& strEnd )
{
    if( start == kPeriodDay )
    {
        strStart = QObject::tr("CreationTime");
        strEnd = QString( "%1 Days" ).arg( end );
    }
    else if( start == kPeriodMonth )
    {
        strStart = QObject::tr("CreationTime");
        strEnd = QString( "%1 Months" ).arg( end );
    }
    else if( start == kPeriodYear )
    {
        strStart = QObject::tr("CreationTime");
        strEnd = QString( "%1 Years" ).arg( end );
    }
    else
    {
        strStart = getDateTime( start );
        strEnd = getDateTime( end );
    }
}

const QString getValueFromExtList( const QString strExtName, JExtensionInfoList *pExtList )
{
    QString strValue;

    JExtensionInfoList *pCurList = NULL;

    pCurList = pExtList;

    while( pCurList )
    {
        QString strSN;

        strSN = pCurList->sExtensionInfo.pOID;

        if( strSN == strExtName )
        {
            strValue = pCurList->sExtensionInfo.pValue;
            break;
        }

        pCurList = pCurList->pNext;
    }

    return strValue;
}
