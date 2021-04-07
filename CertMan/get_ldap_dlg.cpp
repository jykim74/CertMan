#include "get_ldap_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_ldap.h"
#include "js_pki.h"
#include "js_pki_x509.h"

const char *kUsedURI = "UsedURI";
const char *kLDAP = "LDAP";

static QStringList sDataAttributeList = {
    "caCertificate", "signCertificate", "userCertificate", "certificateRevocationList", "authorityRevocationList"
};

static QStringList sFilterList = {
    "BASE"
};

GetLDAPDlg::GetLDAPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

GetLDAPDlg::~GetLDAPDlg()
{

}


void GetLDAPDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void GetLDAPDlg::accept()
{
    int ret = -1;
    int nType = -1;
    BIN binData = {0,0};
    LDAP *pLD = NULL;

    if( mUseURICheck->isChecked() )
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
        nType = JS_LDAP_getType( mSearchCombo->currentText().toStdString().c_str() );
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

void GetLDAPDlg::initUI()
{
    mSearchCombo->addItems(sDataAttributeList);
    mFilterCombo->addItems(sFilterList);

    mLDAPPortText->setText( "389" );
    mFilterText->setText( "(objectclass=*)" );

    connect( mUseURICheck, SIGNAL(clicked()), this, SLOT(clickUseURI()));
}

void GetLDAPDlg::initialize()
{

}

QStringList GetLDAPDlg::getUsedURI()
{
    QSettings settings;
    QStringList retList;

    settings.beginGroup( kUsedURI );
    retList = settings.value( kLDAP ).toStringList();
    settings.endGroup();

    return retList;
}

void GetLDAPDlg::saveUsedURI( const QString &strURL )
{

    QSettings settings;
    settings.beginGroup( kUsedURI );
    QStringList list = settings.value( kLDAP ).toStringList();
    list.removeAll( strURL );
    list.insert( 0, strURL );
    settings.setValue( kLDAP, list );
    settings.endGroup();
}

void GetLDAPDlg::clickUseURI()
{
    if( mUseURICheck->isChecked() )
    {
        mLDAPHostText->setEnabled(false);
        mLDAPPortText->setEnabled(false);
        mDNText->setEnabled(false);
        mFilterText->setEnabled(false);
        mSearchCombo->setEnabled(false);
        mFilterCombo->setEnabled(false);
        mURICombo->setEnabled(true);
        mURICombo->setEditable(true);
        mURICombo->addItems(getUsedURI());
        mURICombo->clearEditText();
    }
    else
    {
        mLDAPHostText->setEnabled(true);
        mLDAPPortText->setEnabled(true);
        mDNText->setEnabled(true);
        mFilterText->setEnabled(true);
        mSearchCombo->setEnabled(true);
        mFilterCombo->setEnabled(true);
        mURICombo->setEnabled(false);
        mURICombo->setEditable(false);
    }

}


int GetLDAPDlg::ImportCert( const BIN *pCert )
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
    if( mSearchCombo->currentIndex() == 0 )
        cert.setCA(1);

    dbMgr->addCertRec( cert );

    if( pHexCert ) JS_free( pHexCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return 0;
}

int GetLDAPDlg::ImportCRL( const BIN *pCRL )
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
