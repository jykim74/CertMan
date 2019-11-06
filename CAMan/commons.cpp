#include <QString>
#include <QtCore>

#include "commons.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"


int setKeyUsage( BIN *pBinExt, const QString strVal )
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

int setCRLNum( BIN *pBinExt, const QString strVal )
{
    int ret = 0;

    ret = JS_PKI_setCRLNumberValue( pBinExt, strVal.toStdString().c_str() );

    return ret;
}

int setCertPolicy( BIN *pBinExt, const QString strVal )
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
    return ret;
}

int setSKI( BIN *pBinExt, const QString strVal )
{
    int ret = 0;

    ret = JS_PKI_setSubjectKeyIdentifierValue( pBinExt, strVal.toStdString().c_str() );

    return ret;
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
        ret = setKeyUsage( &binExt, strVal );
    }
    else if( strSN == kExtNameCRLNum )
    {
        ret = setCRLNum( &binExt, strVal );
    }
    else if( strSN == kExtNamePolicy )
    {
        ret = setCertPolicy( &binExt, strVal );
    }
    else if( strSN == kExtNameSKI )
    {
        ret = setSKI( &binExt, strVal );
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
