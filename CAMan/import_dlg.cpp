#include <QFileDialog>

#include "import_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_pki_tools.h"

static QStringList sDataTypeList = {
    "PrivateKey", "Encrypted PrivateKey", "Request(CSR)", "Certificate", "CRL", "PFX"
};

ImportDlg::ImportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
}

ImportDlg::~ImportDlg()
{

}


void ImportDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void ImportDlg::accept()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    QString strPath = mPathText->text();
    QString strPass = mPasswordText->text();

    if( strPass.isEmpty() )
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
    return 0;
}

int ImportDlg::ImportCRL( const BIN *pCRL )
{
    return 0;
}

int ImportDlg::ImportRequest( const BIN *pCSR )
{
    return 0;
}

int ImportDlg::ImportPFX( const BIN *pPFX )
{
    return 0;
}
