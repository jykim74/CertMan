#include <QFileDialog>

#include "import_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_tools.h"
#include "js_pki_x509.h"

static QStringList sDataTypeList = {
    "PrivateKey", "Encrypted PrivateKey", "Request(CSR)", "Certificate", "CRL", "PFX"
};

ImportDlg::ImportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    initialize();
}

ImportDlg::~ImportDlg()
{

}

void ImportDlg::setType(int index)
{
    mDataTypeCombo->setCurrentIndex(index);
}

void ImportDlg::accept()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    QString strPath = mPathText->text();
    QString strPass = mPasswordText->text();

    if( strPath.isEmpty() )
    {
        manApplet->warningBox( tr( "select file to import"), this );
        return;
    }

    int nSelType = mDataTypeCombo->currentIndex();

    if( nSelType == 1 || nSelType == 5 )
    {
        manApplet->warningBox( tr("insert password"), this );
        mPasswordText->setFocus();
        return;
    }

    BIN binSrc = {0,0};
    JS_BIN_fileRead( strPath.toStdString().c_str(), &binSrc );

    if( nSelType == 0 || nSelType == 1 )
    {
        if( nSelType == 1 )
        {
            int ret = 0;
            BIN binInfo = {0,0};
            BIN binPri = {0,0};

            ret = JS_PKI_decryptRSAPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );
            if( ret != 0 )
                ret = JS_PKI_decryptECPrivateKey( strPass.toStdString().c_str(), &binSrc, &binInfo, &binPri );

            if( ret == 0 ) ImportKeyPair( &binPri );

            JS_BIN_reset( &binInfo );
            JS_BIN_reset( &binPri );
        }
        else
            ImportKeyPair( &binSrc );
    }
    else if( nSelType == 2 )
    {
        ImportRequest( &binSrc );
    }
    else if( nSelType == 3 )
    {
        ImportCert( &binSrc );
    }
    else if( nSelType == 4 )
    {
        ImportCRL( &binSrc );
    }
    else if( nSelType == 5 )
    {
        ImportPFX( &binSrc );
    }

    JS_BIN_reset( &binSrc );
    QDialog::accept();
}

void ImportDlg::initUI()
{
    mDataTypeCombo->addItems(sDataTypeList);

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT( clickFind()));
    connect( mDataTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
}

void ImportDlg::initialize()
{

}


void ImportDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Import files"),
                                                     QDir::currentPath(),
                                                     tr("Cert Files (*.crt);;Key Files (*.key);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}

void ImportDlg::dataTypeChanged( int index )
{
    if( index == 1 || index == 5 )
        mPasswordText->setEnabled(true);
    else {
        mPasswordText->setEnabled(false);
    }
}

int ImportDlg::ImportKeyPair( const BIN *pPriKey )
{
    int ret = 0;
    BIN binPub = {0,0};
    QString strAlg;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return -1;

    KeyPairRec keyPair;
    char *pHexPri = NULL;
    char *pHexPub = NULL;

    ret = JS_PKI_getPubKeyFromPriKey( JS_PKI_KEY_TYPE_RSA, pPriKey, &binPub );
    if( ret == 0 )
        strAlg = "RSA";
    else
    {
        ret = JS_PKI_getPubKeyFromPriKey( JS_PKI_KEY_TYPE_ECC, pPriKey, &binPub );
        if( ret == 0 ) strAlg = "EC";
    }

    if( ret != 0  ) return -1;

    JS_BIN_encodeHex( pPriKey, &pHexPri );
    JS_BIN_encodeHex( &binPub, &pHexPub );

    keyPair.setAlg( strAlg );
    keyPair.setName( mNameText->text() );
    keyPair.setPublicKey( pHexPub );
    keyPair.setPublicKey( pHexPri );
    keyPair.setParam( "Imported" );

    ret = dbMgr->addKeyPairRec( keyPair );

    if( pHexPri ) JS_free( pHexPri );
    if( pHexPub ) JS_free( pHexPub );
    JS_BIN_reset( &binPub );

    return ret;
}

int ImportDlg::ImportCert( const BIN *pCert )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
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

    dbMgr->addCertRec( cert );

    if( pHexCert ) JS_free( pHexCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return 0;
}

int ImportDlg::ImportCRL( const BIN *pCRL )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
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

int ImportDlg::ImportRequest( const BIN *pCSR )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return -1;

    ReqRec  req;
    JReqInfo   sReqInfo;
    char *pHexCSR = NULL;
    JExtensionInfoList *pExtInfoList = NULL;
    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    ret = JS_PKI_getReqInfo( pCSR, &sReqInfo, &pExtInfoList );
    if( ret != 0 ) return ret;

    JS_BIN_encodeHex( pCSR, &pHexCSR );

    req.setCSR( pHexCSR );
    req.setDN( sReqInfo.pSubjectDN );
    req.setHash( sReqInfo.pSignAlgorithm );
    req.setName( mNameText->text() );

    dbMgr->addReqRec( req );
    if( pHexCSR ) JS_free( pHexCSR );
    JS_PKI_resetReqInfo( &sReqInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return 0;
}

int ImportDlg::ImportPFX( const BIN *pPFX )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return -1;

    BIN binCert = {0,0};
    BIN binPri = {0,0};

    const char *pPasswd = mPasswordText->text().toStdString().c_str();

    ret = JS_PKI_decodePFX( pPFX, pPasswd, &binPri, &binCert );
    if( ret != 0 ) return ret;

    ImportCert( &binCert );
    ImportKeyPair( &binPri );

    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPri );

    return 0;
}
