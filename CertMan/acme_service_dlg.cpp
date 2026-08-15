#include <QLayout>
#include <QSettings>

#include "js_gen.h"
#include "js_pki.h"
#include "js_tsp.h"

#include "man_applet.h"
#include "ca_man_dlg.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"
#include "profile_man_dlg.h"
#include "view_cert_profile_dlg.h"
#include "commons.h"

#include "acme_service_dlg.h"

const QString kACMEDefault = "ACMEDefault";

ACMEServiceDlg::ACMEServiceDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    acme_srv_ = nullptr;

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mStopBtn, SIGNAL(clicked()), this, SLOT(clickStop()));

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

    connect( mHTTP01FixCheck, SIGNAL(clicked()), this, SLOT(checkHTTP01ServerFix()));
    connect( mDNS01FixCheck, SIGNAL(clicked()), this, SLOT(checkDNS01ServerFix()));
    connect( mTLS_ALPN01FixCheck, SIGNAL(clicked()), this, SLOT(checkTLS_ALPN01ServerFix()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

ACMEServiceDlg::~ACMEServiceDlg()
{
    if( acme_srv_ ) delete acme_srv_;
}

void ACMEServiceDlg::initUI()
{
    mChallValidCheck->setChecked( true );
    mPortText->setText( QString("%1").arg( JS_ACME_PORT ));

    mHTTP01HostText->setText( "127.0.0.1" );
    mHTTP01PortText->setText( "80" );
    mDNS01HostText->setText( "127.0.0.1" );
    mDNS01PortText->setText( "53" );
    mTLS_ALPN01HostText->setText( "127.0.0.1" );
    mTLS_ALPN01PortText->setText( "443" );
}

void ACMEServiceDlg::initialize()
{
    QString strDefault = getDefault();
    QStringList listDefault;

    if( strDefault.length() > 4 ) listDefault = strDefault.split(":");
    /* Port:TLS:ProfileNum:CANum:TLSNum:AlwaysValid:HTTP01:DNS01:TLS_ALPN01 */

    if( listDefault.size() >= 9 )
    {
        int nPort = listDefault.at(0).toInt();
        bool bTLS = listDefault.at(1).toInt();
        int nProfileNum = listDefault.at(2).toInt();
        int nCANum = listDefault.at(3).toInt();
        int nTLSNum = listDefault.at(4).toInt();
        int bChallValid = listDefault.at(5).toInt();
        QString strHTTP01 = listDefault.at(6);
        QString strDNS01 = listDefault.at(7);
        QString strTLS_ALPN01 = listDefault.at(8);

        if( nPort > 0 ) mPortText->setText( QString("%1").arg(nPort));
        mTLSCheck->setChecked( bTLS );
        if( nProfileNum > 0 ) mProfileNumText->setText( QString("%1").arg( nProfileNum ));
        if( nCANum > 0 ) mNumText->setText( QString("%1").arg( nCANum ));
        if( nTLSNum > 0 ) mTLSNumText->setText( QString("%1").arg( nTLSNum ));
        mChallValidCheck->setChecked( bChallValid );

        mSetDefaultCheck->setChecked( true );

        QStringList listHTTP01 = strHTTP01.split( "|" );

        if( strHTTP01.length() > 1 ) mHTTP01Group->setChecked( true );
        if( listHTTP01.size() >= 3 )
        {
            mHTTP01FixCheck->setChecked(true);
            mHTTP01HostText->setText( listHTTP01.at(1) );
            mHTTP01PortText->setText( listHTTP01.at(2) );
        }

        QStringList listDNS01 = strDNS01.split( "|" );

        if( strDNS01.length() > 1 ) mDNS01Group->setChecked( true );
        if( listDNS01.size() >= 3 )
        {
            mDNS01FixCheck->setChecked(true);
            mDNS01HostText->setText( listDNS01.at(1) );
            mDNS01PortText->setText( listDNS01.at(2) );
        }

        QStringList listTLS_ALPN01 = strTLS_ALPN01.split( "|" );

        if( strTLS_ALPN01.length() > 1 ) mTLS_ALPN01Group->setChecked( true );
        if( listTLS_ALPN01.size() >= 3 )
        {
            mTLS_ALPN01FixCheck->setChecked(true);
            mTLS_ALPN01HostText->setText( listTLS_ALPN01.at(1) );
            mTLS_ALPN01PortText->setText( listTLS_ALPN01.at(2) );
        }
    }

    checkHTTP01ServerFix();
    checkDNS01ServerFix();
    checkTLS_ALPN01ServerFix();

    checkTLS();
}

QString ACMEServiceDlg::getDefault()
{
    QSettings settings;
    QString strDefault;

    settings.beginGroup( kSettingBer );
    strDefault = settings.value( kACMEDefault ).toString();
    settings.endGroup();

    return strDefault;
}

void ACMEServiceDlg::setDefault( const QString strDefault )
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kACMEDefault, strDefault );
    settings.endGroup();
}

void ACMEServiceDlg::clickStart()
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
    QString strHTTP01Val;
    QString strDNS01Val;
    QString strTLS_ALPN01Val;

    if( acme_srv_ != nullptr )
    {
        manApplet->warningBox( tr("The server has already started."), this );
        return;
    }

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
    int nTLSNum = -1;
    int nChallFlag = 0;
    bool bChallValid = mChallValidCheck->isChecked();

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

    if( acme_srv_ ) delete acme_srv_;

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    manApplet->getPriKey( keyPair.getPrivateKey(), &binPriKey );

    if( mTLSCheck->isChecked() == true )
    {
        nTLSNum = mTLSNumText->text().toInt();

        int ret = dbMgr->getCertRec( nTLSNum, certRec );
        if( ret != 0 )
        {
            manApplet->warningBox( tr("failed to get TLS certificate" ), this );
            goto end;
        }

        ret = dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
        if( ret != 0 )
        {
            manApplet->warningBox( tr("failed to get TLS private key" ), this );
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

    acme_srv_ = new ACMEServer;
    nPort = strPort.toInt();
    acme_srv_->setLogEdit( mLogText );
    acme_srv_->setCACert( &binCert );
    acme_srv_->setCANum( nNum );
    acme_srv_->setProfileNum( nProfileNum );
    acme_srv_->setCAPriKey( &binPriKey, bP11 );
    acme_srv_->setChallValid( bChallValid );

    if( mHTTP01Group->isChecked() )
    {
        strHTTP01Val = "true";

        if( mHTTP01FixCheck->isChecked() )
        {
            QString strHost = mHTTP01HostText->text();
            QString strPort = mHTTP01PortText->text();

            strHTTP01Val += QString( "|%1|%2" ).arg( strHost ).arg( strPort );
        }

        acme_srv_->setHTTP01( strHTTP01Val );
    }

    if( mDNS01Group->isChecked() )
    {
        strDNS01Val = "true";

        if( mDNS01FixCheck->isChecked() )
        {
            QString strHost = mDNS01HostText->text();
            QString strPort = mDNS01PortText->text();

            strDNS01Val += QString( "|%1|%2" ).arg( strHost ).arg( strPort );
        }

        acme_srv_->setDNS01( strDNS01Val );
    }

    if( mTLS_ALPN01Group->isChecked() )
    {
        strTLS_ALPN01Val = "true";

        if( mTLS_ALPN01FixCheck->isChecked() )
        {
            QString strHost = mTLS_ALPN01HostText->text();
            QString strPort = mTLS_ALPN01PortText->text();

            strTLS_ALPN01Val += QString( "|%1|%2" ).arg( strHost ).arg( strPort );
        }

        acme_srv_->setTLS_ALPN01( strTLS_ALPN01Val );
    }

    if( mTLSCheck->isChecked() == true )
    {
        acme_srv_->setTLS( &binTLSCert, &binTLSPriKey );
    }

    ret = acme_srv_->startServer( nPort );
    if( ret != JSR_OK )
    {
        manApplet->warningBox( tr( "failed to start server: %1").arg(ret), this );
        goto end;
    }

    mStartBtn->setStyleSheet( kColorBackGreen );

    if( mSetDefaultCheck->isChecked() == true )
    {
        /* Port:TLS:ProfileNum:CANum:TLSNum */
        QString strDefault = QString( "%1:%2:%3:%4:%5:%6:%7:%8:%9" )
                                 .arg( nPort )
                                 .arg( mTLSCheck->isChecked() )
                                 .arg( nProfileNum )
                                 .arg(nNum)
                                 .arg( nTLSNum )
                                 .arg( bChallValid )
                                 .arg(strHTTP01Val)
                                 .arg(strDNS01Val)
                                 .arg(strTLS_ALPN01Val);

        setDefault( strDefault );
    }
    else
    {
        setDefault( "" );
    }

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binTLSCert );
    JS_BIN_reset( &binTLSPriKey );
}

void ACMEServiceDlg::clickStop()
{
    mStartBtn->setStyleSheet( "" );
    if( acme_srv_ == nullptr ) return;

    acme_srv_->deleteLater();
    acme_srv_ = nullptr;
}

void ACMEServiceDlg::clickLogClear()
{
    mLogText->clear();
}

void ACMEServiceDlg::clickSelect()
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

void ACMEServiceDlg::clickView()
{
    int num = mNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void ACMEServiceDlg::changeNum()
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

void ACMEServiceDlg::clickProfileSelect()
{
    ProfileManDlg profileMan;
    profileMan.setTitle( tr( "Select a profile" ));
    profileMan.setMode( ProfileManModeSelectCertProfile );

    if( profileMan.exec() == QDialog::Accepted )
    {
        mProfileNumText->setText( QString("%1").arg( profileMan.getNum() ));
    }
}

void ACMEServiceDlg::clickProfileView()
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

void ACMEServiceDlg::changeProfileNum()
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

void ACMEServiceDlg::checkTLS()
{
    mTLSGroup->setEnabled( mTLSCheck->isChecked() );
}

void ACMEServiceDlg::clickTLSSelect()
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

void ACMEServiceDlg::clickTLSView()
{
    int num = mTLSNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void ACMEServiceDlg::changeTLSNum()
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

void ACMEServiceDlg::checkHTTP01ServerFix()
{
    bool bVal = mHTTP01FixCheck->isChecked();

    mHTTP01HostText->setEnabled( bVal );
    mHTTP01PortText->setEnabled( bVal );
}

void ACMEServiceDlg::checkDNS01ServerFix()
{
    bool bVal = mDNS01FixCheck->isChecked();

    mDNS01HostText->setEnabled( bVal );
    mDNS01PortText->setEnabled( bVal );
}

void ACMEServiceDlg::checkTLS_ALPN01ServerFix()
{
    bool bVal = mTLS_ALPN01FixCheck->isChecked();

    mTLS_ALPN01HostText->setEnabled( bVal );
    mTLS_ALPN01PortText->setEnabled( bVal );
}
