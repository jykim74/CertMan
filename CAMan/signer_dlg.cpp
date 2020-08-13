#include <QFileDialog>

#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "signer_dlg.h"
#include "signer_rec.h"

#include "js_bin.h"
#include "js_pki_x509.h"

static QStringList sTypeList = { "REG Signer", "OCSP Signer" };

SignerDlg::SignerDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    initialize();
}

SignerDlg::~SignerDlg()
{

}

void SignerDlg::setType(int nType)
{
    mTypeCombo->setCurrentIndex( nType );
}

void SignerDlg::findCert()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Certificate files"),
                                                     QDir::currentPath(),
                                                     tr("Cert Files (*.crt);;DER Files (*.der);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mCertPathText->setText(fileName);
}

void SignerDlg::accept()
{
    BIN binCert = {0,0};
    JCertInfo   sCertInfo;
    JExtensionInfoList  *pExtInfoList = NULL;
    SignerRec signer;
    char *pCert = NULL;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    QString strCertPath = mCertPathText->text();

    JS_BIN_fileRead( strCertPath.toStdString().c_str(), &binCert );
    JS_BIN_encodeHex( &binCert, &pCert );

    JS_PKI_getCertInfo( &binCert, &sCertInfo, &pExtInfoList );

    int nType = mTypeCombo->currentIndex();
    time_t now_t = time(NULL);

    signer.setRegTime( now_t );
    signer.setType( nType );
    signer.setDN( sCertInfo.pSubjectName );
    signer.setDNHash( sCertInfo.pDNHash );
    signer.setStatus( mStatusText->text().toInt() );
    signer.setCert( pCert );
    signer.setDesc( mDescText->toPlainText() );

    dbMgr->addSignerRec( signer );

    if( pCert ) JS_free( pCert );
    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    QDialog::accept();
    manApplet->mainWindow()->createRightSignerList(nType);
}

void SignerDlg::initialize()
{

}

void SignerDlg::initUI()
{
    mTypeCombo->addItems(sTypeList);
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
}
