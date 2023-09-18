#include "get_uri_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_ldap.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_http.h"

const char *kUsedURI = "UsedURI";
const char *kURL = "URL";

static QStringList sDataAttributeList = {
    "caCertificate", "signCertificate", "userCertificate", "certificateRevocationList", "authorityRevocationList"
};

static QStringList sFilterList = {
    "BASE"
};

GetURIDlg::GetURIDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mClearUsedURIBtn, SIGNAL(clicked()), this, SLOT(clickClearUsedURI()));
    connect( mGetBtn, SIGNAL(clicked()), this, SLOT(clickGet()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initUI();
}

GetURIDlg::~GetURIDlg()
{

}


void GetURIDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void GetURIDlg::accept()
{
    int ret = -1;
    int nType = -1;
    BIN binData = {0,0};
    LDAP *pLD = NULL;

    if( mUseLDAPCheck->isChecked() == false )
    {
        char sHost[1024];
        char sDN[1024];
        int nPort = -1;
        int nScope = -1;
        char sFilter[256];
        char sAttribute[256];

        QString strURI = mURICombo->currentText();

        ret = JS_LDAP_parseURI( strURI.toStdString().c_str(), sHost, &nPort, sDN, &nScope, sFilter, sAttribute );
        nType = JS_LDAP_getType( sAttribute );

        pLD = JS_LDAP_init( sHost, nPort );

        ret = JS_LDAP_bind( pLD, NULL, NULL );
        ret = JS_LDAP_getData( pLD, sDN, sFilter, nType, nScope, &binData );

        saveUsedURI( strURI );
    }
    else
    {
        nType = JS_LDAP_getType( mTypeCombo->currentText().toStdString().c_str() );
        pLD = JS_LDAP_init( mLDAPHostText->text().toStdString().c_str(), mLDAPPortText->text().toInt());
        ret = JS_LDAP_bind( pLD, NULL, NULL );
        ret = JS_LDAP_getData( pLD,
                         mDNText->text().toStdString().c_str(),
                         mFilterText->text().toStdString().c_str(),
                         nType,
                         LDAP_SCOPE_BASE,
                         &binData );
    }

    if( nType == JS_LDAP_TYPE_CERTIFICATE_REVOCATION_LIST  ||
            nType == JS_LDAP_TYPE_AUTHORITY_REVOCATION_LIST )
        ret = ImportCRL( &binData );
    else
        ret = ImportCert( &binData );

    if( pLD ) JS_LDAP_close( pLD );
    JS_BIN_reset( &binData );

    if( ret == 0 ) QDialog::accept();
}

void GetURIDlg::initUI()
{
    mURICombo->setEditable( true );

    mTypeCombo->addItems(sDataAttributeList);
    mScopeCombo->addItems(sFilterList);

    mLDAPHostText->setText( "127.0.0.1" );
    mLDAPPortText->setText( "389" );
    mFilterText->setText( "(objectclass=*)" );

    connect( mUseLDAPCheck, SIGNAL(clicked()), this, SLOT(clickUseLDAPHost()));
}

void GetURIDlg::initialize()
{
    clickUseLDAPHost();
}

QStringList GetURIDlg::getUsedURI()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kUsedURI );
    retList = settings.value( kURL ).toStringList();
    settings.endGroup();

    return retList;
}

void GetURIDlg::saveUsedURI( const QString &strURL )
{

    QSettings settings;
    settings.beginGroup( kUsedURI );
    QStringList list = settings.value( kURL ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kURL, list );
    settings.endGroup();
}

void GetURIDlg::clickUseLDAPHost()
{
    bool bVal = mUseLDAPCheck->isChecked();

    mLDAPHostGroup->setEnabled( bVal );
    mURIAddrGroup->setEnabled( !bVal );
}

void GetURIDlg::clickClearUsedURI()
{
    QSettings settings;
    settings.beginGroup( kUsedURI );
    settings.setValue( kURL, "" );
    settings.endGroup();

    mURICombo->clearEditText();
    mURICombo->clear();
}

void GetURIDlg::clickGet()
{
    int ret = -1;
    bool bCRL = false;
    BIN binData = {0,0};
    JCertInfo sCertInfo;
    JCRLInfo sCRLInfo;
    QString strTarget;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    if( mUseLDAPCheck->isChecked() )
    {
        QString strDN = mDNText->text();
        if( strDN.length() < 1 )
        {
            manApplet->warningBox( tr( "Insert DN value" ), this );
            return;
        }

        ret = getLDAP( &binData );
        if( ret != 0 ) goto end;
    }
    else
    {
        QString strURL = mURICombo->currentText();
        if( strURL.length() < 1 )
        {
            manApplet->warningBox( tr( "Insert URI value" ), this );
            return;
        }

        QString strURI = getValidURL();
        manApplet->log( QString( "Get Address: %1").arg( strURI ));

        QStringList strList = strURI.split( ":" );
        if( strList.size() < 2 )
        {
            ret = -1;
            goto end;
        }

        QString strProto = strList.at(0);

        if( strProto == "ldap" )
            ret = getLDAP( &binData );
        else if( strProto == "http" || strProto == "https" )
            ret = getHTTP( &binData );
        else
        {
            manApplet->elog( QString("Invalid Protocol : %1").arg( strProto));
            ret = -1;
        }

        if( ret != 0 ) goto end;
    }

    ret = JS_PKI_getCertInfo( &binData, &sCertInfo, NULL );
    if( ret != 0 )
    {
        ret = JS_PKI_getCRLInfo( &binData, &sCRLInfo, NULL, NULL );
        if( ret != 0 )
        {
            manApplet->elog( "Invalid data" );
            goto end;
        }
        else
        {
            bCRL = true;
        }
    }
    else
    {
        bCRL = false;
    }

    if( bCRL == true )
    {
        ret = ImportCRL( &binData );
        strTarget = tr( "CRL" );
    }
    else
    {
        ret = ImportCert( &binData );
        strTarget = tr( "Certificate" );
    }

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_PKI_resetCRLInfo( &sCRLInfo );
    JS_BIN_reset( &binData );

    if( ret == 0 )
    {
        if( bCRL == false )
            manApplet->mainWindow()->createRightCertList(-2);
        else
            manApplet->mainWindow()->createRightCRLList(-2);

        manApplet->messageBox( tr( "Success to get URI %1" ).arg( strTarget ), this );
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "fail to get URI data: %1" ).arg( ret ), this );
        QDialog::reject();
    }
}

const QString GetURIDlg::getValidURL()
{
    QString strURL = mURICombo->currentText();

    strURL.remove( "url=" );
    strURL.remove( "uri=" );
    strURL.remove( "URL=" );
    strURL.remove( "URI=" );

    return strURL.simplified();
}

int GetURIDlg::getLDAP( BIN *pData )
{
    int ret = -1;
    LDAP *pLD = NULL;

    int nPort = -1;
    QString strFilter;
    int nScope = LDAP_SCOPE_BASE;
    int nType = -1;
    QString strDN = "";
    QString strHost = "";
    QString strURI;


    if( mUseLDAPCheck->isChecked() )
    {
        strHost = mLDAPHostText->text();
        nPort = mLDAPPortText->text().toInt();
        strDN = mDNText->text();
        strFilter = mFilterText->text();
    }
    else {
        char    sHost[1024];
        char    sDN[1024];
        char    sFilter[256];
        char    sAttribute[256];

        memset( sHost, 0x00, sizeof(sHost));
        memset( sDN, 0x00, sizeof(sDN) );
        memset( sFilter, 0x00, sizeof(sFilter));
        memset( sAttribute, 0x00, sizeof(sAttribute));

        strURI = getValidURL();

        ret = JS_LDAP_parseURI( strURI.toStdString().c_str(), sHost, &nPort, sDN, &nScope, sFilter, sAttribute );
        nType = JS_LDAP_getType( sAttribute );

        if( sHost[0] != 0x00 ) strHost = sHost;
        if( sDN[0] != 0x00 ) strDN = sDN;
        if( sFilter[0] != 0 ) strFilter = sFilter;
        if( strFilter.length() < 1 ) strFilter = mFilterText->text();
    }

    if( nType < 0 ) nType = JS_LDAP_getType( mTypeCombo->currentText().toStdString().c_str() );
    if( nScope < 0 ) nScope = LDAP_SCOPE_BASE;


    pLD = JS_LDAP_init( strHost.toStdString().c_str(), nPort );
    if( pLD == NULL )
    {
        manApplet->warningBox( tr("fail to connnect LDAP server" ), this );
        return -1;
    }

    ret = JS_LDAP_bind( pLD, NULL, NULL );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to bind LDAP server"), this );
        goto end;
    }

    ret = JS_LDAP_getData( pLD, strDN.toStdString().c_str(), strFilter.toStdString().c_str(), nType, nScope, pData );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to get data from LDAP server"), this );
        goto end;
    }

end :
    if( pLD ) JS_LDAP_close(pLD);
    return ret;
}

int GetURIDlg::getHTTP( BIN *pData )
{
    int ret = 0;
    int nStatus = 0;

    QString strURI = getValidURL();

    ret = JS_HTTP_requestGetBin2( strURI.toStdString().c_str(), NULL, NULL, &nStatus, pData );
    if( ret != 0 ) manApplet->log( QString( "fail to get http: %1").arg(ret));

    return ret;
}


int GetURIDlg::ImportCert( const BIN *pCert )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    char *pHexCert = NULL;
    JCertInfo sCertInfo;
    CertRec     cert;
    JExtensionInfoList *pExtInfoList = NULL;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( pCert, &sCertInfo, &pExtInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCert, &pHexCert );

    cert.setCert( pHexCert );
    cert.setSubjectDN( sCertInfo.pSubjectName );
    cert.setIssuerNum( -2 );
    cert.setSignAlg( sCertInfo.pSignAlgorithm );

    if( strcasecmp( sCertInfo.pIssuerName, sCertInfo.pSubjectName ) == 0 )
        cert.setSelf(1);

    /* need to check IsCA */
    if( mTypeCombo->currentIndex() == 0 )
        cert.setCA(1);

    dbMgr->addCertRec( cert );

    if( pHexCert ) JS_free( pHexCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return 0;
}

int GetURIDlg::ImportCRL( const BIN *pCRL )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    JCRLInfo sCRLInfo;
    char *pHexCRL = NULL;
    CRLRec crl;
    JExtensionInfoList *pExtInfoList = NULL;
    JRevokeInfoList *pRevokeInfoList = NULL;

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    ret = JS_PKI_getCRLInfo( pCRL, &sCRLInfo, &pExtInfoList, &pRevokeInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCRL, &pHexCRL );

    crl.setCRL( pHexCRL );
    crl.setSignAlg( sCRLInfo.pSignAlgorithm );
    crl.setIssuerNum( -2 );

    dbMgr->addCRLRec( crl );

    if( pHexCRL ) JS_free( pHexCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pRevokeInfoList ) JS_PKI_resetRevokeInfoList( &pRevokeInfoList );

    return 0;
}
