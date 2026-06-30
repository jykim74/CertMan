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
#include "commons.h"

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

    connect( mTLSCheck, SIGNAL(clicked()), this, SLOT(checkTLS()));
    connect( mTLSSelectBtn, SIGNAL(clicked()), this, SLOT(clickTLSSelect()));
    connect( mTLSViewBtn, SIGNAL(clicked()), this, SLOT(clickTLSView()));
    connect( mTLSNumText, SIGNAL(textChanged(QString)), this, SLOT(changeTLSNum()));

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
}

void CAServiceDlg::initialize()
{
    checkTLS();
}

void CAServiceDlg::clickStart()
{
    int ret = 0;
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};
    BIN binTLSCert = {0,0};
    BIN binTLSPriKey = {0,0};

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    QString strPort = mPortText->text();

    bool bP11 = false;
    int nPort = -1;

    if( strPort.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a port" ), this );
        mPortText->setFocus();

        return;
    }

    CertRec certRec;
    KeyPairRec keyPair;

    int nNum = mNumText->text().toInt();
    int nProfileNum = mProfileNumText->text().toInt();

    if( nProfileNum <= 0 )
    {
        manApplet->warningBox( tr( "Select a profile" ), this );
        return;
    }

    ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get CA certificate" ), this );
        return;
    }

    ret = dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get CA private key" ), this );
        return;
    }

    bP11 = isPKCS11Private( keyPair.getAlg() );

    if( ca_srv_ ) delete ca_srv_;

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    manApplet->getPriKey( keyPair.getPrivateKey(), &binPriKey );

    if( mTLSCheck->isChecked() == true )
    {
        nNum = mTLSNumText->text().toInt();

        int ret = dbMgr->getCertRec( nNum, certRec );
        if( ret != 0 )
        {
            manApplet->warningBox( tr("failed to get TSP certificate" ), this );
            goto end;
        }

        ret = dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
        if( ret != 0 )
        {
            manApplet->warningBox( tr("failed to get TSP private key" ), this );
            goto end;
        }

        if( isPKCS11Private( keyPair.getAlg() ) == true )
        {
            manApplet->warningBox( tr("TLS does not support PKCS11"), this );
            goto end;
        }

        JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binTLSCert );
        manApplet->getPriKey( keyPair.getPrivateKey(), &binTLSPriKey );
    }

    ca_srv_ = new CAServer;
    nPort = strPort.toInt();
    ca_srv_->setLogEdit( mLogText );
    ca_srv_->setCACert( &binCert );
    ca_srv_->setCANum( nNum );
    ca_srv_->setProfileNum( nProfileNum );
    ca_srv_->setCAPriKey( &binPriKey, bP11 );

    if( mTLSCheck->isChecked() == true )
    {
        ca_srv_->setTLS( &binTLSCert, &binTLSPriKey );
    }

    ca_srv_->startServer( nPort );

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binTLSCert );
    JS_BIN_reset( &binTLSPriKey );
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
//    caMan.mSignerCheck->setChecked(true);

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

void CAServiceDlg::checkTLS()
{
    mTLSGroup->setEnabled( mTLSCheck->isChecked() );
}

void CAServiceDlg::clickTLSSelect()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select TLS Server certificate" ));
    caMan.setMode( CAManModeSelectCACert );
    caMan.mSignerCheck->setChecked(true);

    if( caMan.exec() == QDialog::Accepted )
    {
        mTLSNumText->setText(QString("%1").arg( caMan.getNum() ));
    }
}

void CAServiceDlg::clickTLSView()
{
    int num = mTLSNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void CAServiceDlg::changeTLSNum()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int nNum = mTLSNumText->text().toInt();

    CertRec certRec;
    KeyPairRec keyPair;

    int ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        mTLSNumText->clear();
        return;
    }

    mTLSNameText->setText( certRec.getSubjectDN() );

    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mTLSInfoText->setText( keyPair.getDesc() );
}
