#include <QFileDialog>

#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "signer_dlg.h"
#include "signer_rec.h"
#include "commons.h"

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
    QString strPath = manApplet->curFolder();
    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mCertPathText->setText(fileName);
}

void SignerDlg::accept()
{
    int ret = 0;
    BIN binCert = {0,0};
    JCertInfo   sCertInfo;
    JExtensionInfoList  *pExtInfoList = NULL;
    SignerRec signer;
    char *pCert = NULL;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    QString strCertPath = mCertPathText->text();

    int nType = mTypeCombo->currentIndex();
    time_t now_t = time(NULL);

    JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binCert );
    JS_BIN_encodeHex( &binCert, &pCert );

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, &pExtInfoList );
    if( ret != 0 )
    {
        goto end;
    }

    signer.setRegTime( now_t );
    signer.setType( nType );
    signer.setDN( sCertInfo.pSubjectName );
    signer.setDNHash( sCertInfo.pDNHash );
    signer.setStatus( mStatusCombo->currentIndex() );
    signer.setCert( pCert );
    signer.setInfo( mInfoText->toPlainText() );

    dbMgr->addSignerRec( signer );

end :
    if( pCert ) JS_free( pCert );
    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    if( ret == 0 )
    {
        QDialog::accept();
        manApplet->mainWindow()->createRightSignerList(nType);
    }
    else
    {
        manApplet->warningBox( tr( "fail to register signer"), this );
        return;
    }
}

void SignerDlg::initialize()
{
    mStatusCombo->addItems( kStatusList );
}

void SignerDlg::initUI()
{
    mTypeCombo->addItems(sTypeList);
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
}
