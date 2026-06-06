#include <QLayout>

#include "js_gen.h"
#include "js_pki.h"
#include "js_tsp.h"

#include "ocsp_service_dlg.h"
#include "man_applet.h"

#include "man_applet.h"
#include "ca_man_dlg.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"

OCSPServiceDlg::OCSPServiceDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    ocsp_srv_ = nullptr;

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mLogClearBtn, SIGNAL(clicked()), this, SLOT(clickLogClear()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
    connect( mNumText, SIGNAL(textChanged(QString)), this, SLOT(changeNum()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

OCSPServiceDlg::~OCSPServiceDlg()
{
    if( ocsp_srv_ ) delete ocsp_srv_;
}

void OCSPServiceDlg::initUI()
{
    mPortText->setText( QString("%1").arg( JS_OCSP_PORT ));
    mSSLPortText->setText( QString( "%1" ).arg( JS_OCSP_SSL_PORT ));
}

void OCSPServiceDlg::initialize()
{

}

void OCSPServiceDlg::clickStart()
{
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    QString strPort = mPortText->text();

    if( strPort.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a port" ), this );
        mPortText->setFocus();

        return;
    }

    int nNum = mNumText->text().toInt();

    CertRec certRec;
    KeyPairRec keyPair;

    int ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        return;
    }

    ret = dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
    if( ret != 0 )
    {
        return;
    }

    if( ocsp_srv_ ) delete ocsp_srv_;

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    manApplet->getPriKey( keyPair.getPrivateKey(), &binPriKey );

    ocsp_srv_ = new OCSPServer;
    int nPort = strPort.toInt();
    ocsp_srv_->setLogEdit( mLogText );
    ocsp_srv_->setOCSPCert( &binCert );
    ocsp_srv_->setOCSPPriKey( &binPriKey );
    ocsp_srv_->startServer( nPort );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
}

void OCSPServiceDlg::clickLogClear()
{
    mLogText->clear();
}

void OCSPServiceDlg::clickSelect()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select CA certificate" ));
    caMan.setMode( CAManModeSelectCACert );
    caMan.mSignerCheck->setChecked(true);

    if( caMan.exec() == QDialog::Accepted )
    {
        mNumText->setText(QString("%1").arg( caMan.getNum() ));
    }
}

void OCSPServiceDlg::clickView()
{
    int num = mNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void OCSPServiceDlg::changeNum()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int nNum = mNumText->text().toInt();

    CertRec certRec;
    KeyPairRec keyPair;

    int ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        mNumText->clear();
        return;
    }

    mNameText->setText( certRec.getSubjectDN() );

    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mInfoText->setText( keyPair.getDesc() );
}
