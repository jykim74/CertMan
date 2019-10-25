#include "revoke_cert_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "revoke_rec.h"
#include "cert_rec.h"

static QStringList sRevokeReasonList = {
    "unused", "keyCompromise", "CACompromise",
    "affiliationChanged", "superseded", "cessationOfOperation",
    "certificateHold", "privilegeWithdrawn", "AACompromise"
};

RevokeCertDlg::RevokeCertDlg(QWidget *parent) :
    QDialog(parent)
{
    cert_num_ = -1;
    setupUi(this);

    initUI();
}

RevokeCertDlg::~RevokeCertDlg()
{

}

void RevokeCertDlg::setCertNum(int cert_num)
{
    cert_num_ = cert_num;
}

void RevokeCertDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void RevokeCertDlg::initialize()
{
    int ret = -1;
    if( cert_num_ < 0 ) return;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec cert;
    ret = dbMgr->getCertRec( cert_num_, cert );
    if( ret != 0 ) return;

    mSubjectDNText->setText( cert.getSubjectDN() );
    mSerialText->setText( QString("%1").arg(cert.getNum()));

    QDateTime dateTime = QDateTime::currentDateTime();
    mRevokeDateTime->setDateTime( dateTime );
}

void RevokeCertDlg::accept()
{
    int ret = -1;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec cert;
    ret = dbMgr->getCertRec( cert_num_, cert );
    if( ret != 0 ) return;

    int nReason = mReasonCombo->currentIndex();

    RevokeRec revoke;
    revoke.setCertNum( cert_num_ );
    revoke.setIssuerNum( cert.getIssuerNum() );
    revoke.setSerial( QString("%1").arg(cert.getNum()));
    revoke.setReason( nReason );
    revoke.setRevokeDate( mRevokeDateTime->dateTime().toTime_t() );

    dbMgr->addRevokeRec( revoke );
    dbMgr->modCertStatus( cert_num_, 1 );
}

void RevokeCertDlg::initUI()
{
    mReasonCombo->addItems( sRevokeReasonList );
}
