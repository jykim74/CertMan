#include <QLayout>

#include "js_gen.h"
#include "js_pki.h"
#include "js_tsp.h"

#include "ca_service_dlg.h"

#include "man_applet.h"
#include "ca_man_dlg.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"
#include "profile_man_dlg.h"
#include "view_cert_profile_dlg.h"

CAServiceDlg::CAServiceDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    ca_srv_ = nullptr;

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mLogClearBtn, SIGNAL(clicked()), this, SLOT(clickLogClear()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
    connect( mNumText, SIGNAL(textChanged(QString)), this, SLOT(changeNum()));

    connect( mProfileSelectBtn, SIGNAL(clicked()), this, SLOT(clickProfileSelect()));
    connect( mProfileViewBtn, SIGNAL(clicked()), this, SLOT(clickProfileView()));
    connect( mProfileNumText, SIGNAL(textChanged(QString)), this, SLOT(changeProfileNum()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

CAServiceDlg::~CAServiceDlg()
{
    if( ca_srv_ ) delete ca_srv_;
}

void CAServiceDlg::initUI()
{
    mPortText->setText( QString("%1").arg( JS_CMP_PORT ));
    mSSLPortText->setText( QString( "%1" ).arg( JS_CMP_SSL_PORT ));
}

void CAServiceDlg::initialize()
{

}

void CAServiceDlg::clickStart()
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
    int nProfileNum = mProfileNumText->text().toInt();

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

    if( ca_srv_ ) delete ca_srv_;

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    manApplet->getPriKey( keyPair.getPrivateKey(), &binPriKey );

    ca_srv_ = new CAServer;
    int nPort = strPort.toInt();
    ca_srv_->setLogEdit( mLogText );
    ca_srv_->setCACert( &binCert );
    ca_srv_->setCANum( nNum );
    ca_srv_->setProfileNum( nProfileNum );
    ca_srv_->setCAPriKey( &binPriKey );
    ca_srv_->startServer( nPort );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
}

void CAServiceDlg::clickLogClear()
{
    mLogText->clear();
}

void CAServiceDlg::clickSelect()
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

void CAServiceDlg::clickView()
{
    int num = mNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void CAServiceDlg::changeNum()
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

void CAServiceDlg::clickProfileSelect()
{
    ProfileManDlg profileMan;
    profileMan.setTitle( tr( "Select a profile" ));
    profileMan.setMode( ProfileManModeSelectCertProfile );

    if( profileMan.exec() == QDialog::Accepted )
    {
        mProfileNumText->setText( QString("%1").arg( profileMan.getNum() ));
    }
}

void CAServiceDlg::clickProfileView()
{
    QString strNum = mProfileNumText->text();
    if( strNum.length() < 1 )
    {
        manApplet->warningBox( tr("No profile selected"), this );
        return;
    }

    ViewCertProfileDlg certProfile;
    certProfile.setProfile( strNum.toInt() );
    certProfile.exec();
}

void CAServiceDlg::changeProfileNum()
{
    int nNum = mProfileNumText->text().toInt();
    CertProfileRec profile;
    int ret = manApplet->dbMgr()->getCertProfileRec( nNum, profile );
    if( ret != 0 )
    {
        mProfileNumText->clear();
        return;
    }

    mProfileNameText->setText( profile.getName() );
}
