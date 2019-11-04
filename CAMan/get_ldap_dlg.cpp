#include "get_ldap_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_ldap.h"
#include "js_pki.h"
#include "js_pki_x509.h"

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

        ret = JS_LDAP_parseURI( mURIText->text().toStdString().c_str(), sHost, &nPort, sDN, &nScope, sFilter, sAttribute );
        nType = JS_LDAP_getType( sAttribute );

        pLD = JS_LDAP_init( sHost, nPort );

        ret = JS_LDAP_bind( pLD, NULL, NULL );
        ret = JS_LDAP_getData( pLD, sDN, sFilter, nType, nScope, &binData );
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

    connect( mUseURICheck, SIGNAL(clicked()), this, SLOT(clickUseURI()));
}

void GetLDAPDlg::initialize()
{

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
        mURIText->setEnabled(true);
    }
    else
    {
        mLDAPHostText->setEnabled(true);
        mLDAPPortText->setEnabled(true);
        mDNText->setEnabled(true);
        mFilterText->setEnabled(true);
        mSearchCombo->setEnabled(true);
        mFilterCombo->setEnabled(true);
        mURIText->setEnabled(false);
    }

}


int GetLDAPDlg::ImportCert( const BIN *pCert )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return -1;

    char *pHexCert = NULL;
    JSCertInfo sCertInfo;
    CertRec     cert;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    ret = JS_PKI_getCertInfo( pCert, &sCertInfo );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCert, &pHexCert );

    cert.setCert( pHexCert );
    cert.setSubjectDN( sCertInfo.pSubjectName );
    cert.setIssuerNum( -2 );
    cert.setSignAlg( sCertInfo.pSignAlgorithm );

    dbMgr->addCertRec( cert );

    if( pHexCert ) JS_free( pHexCert );
    JS_PKI_resetCertInfo( &sCertInfo );

    return 0;
}

int GetLDAPDlg::ImportCRL( const BIN *pCRL )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return -1;

    JSCRLInfo sCRLInfo;
    char *pHexCRL = NULL;
    CRLRec crl;

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));

    ret = JS_PKI_getCRLInfo( pCRL, &sCRLInfo );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCRL, &pHexCRL );

    crl.setCRL( pHexCRL );
    crl.setSignAlg( sCRLInfo.pSignAlgorithm );
    crl.setIssuerNum( -2 );

    dbMgr->addCRLRec( crl );

    if( pHexCRL ) JS_free( pHexCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );

    return 0;
}
