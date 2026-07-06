#include <QLayout>
#include <QSettings>

#include "js_gen.h"
#include "js_pki.h"
#include "js_tsp.h"

#include "ocsp_service_dlg.h"
#include "man_applet.h"

#include "man_applet.h"
#include "ca_man_dlg.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"
#include "commons.h"

const QString kOCSPDefault = "OCSPDefault";

OCSPServiceDlg::OCSPServiceDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    ocsp_srv_ = nullptr;

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mStopBtn, SIGNAL(clicked()), this, SLOT(clickStop()));

    connect( mLogClearBtn, SIGNAL(clicked()), this, SLOT(clickLogClear()));

    connect( mCASelectBtn, SIGNAL(clicked()), this, SLOT(clickCASelect()));
    connect( mCAViewBtn, SIGNAL(clicked()), this, SLOT(clickCAView()));
    connect( mCANumText, SIGNAL(textChanged(QString)), this, SLOT(changeCANum()));

    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
    connect( mNumText, SIGNAL(textChanged(QString)), this, SLOT(changeNum()));

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

OCSPServiceDlg::~OCSPServiceDlg()
{
    if( ocsp_srv_ ) delete ocsp_srv_;
}

void OCSPServiceDlg::initUI()
{
    mPortText->setText( QString("%1").arg( JS_OCSP_PORT ));
}

void OCSPServiceDlg::initialize()
{
    QString strDefault = getDefault();
    QStringList listDefault;

    if( strDefault.length() > 4 ) listDefault = strDefault.split(":");
    /* Port:TLS:NeedSign:CANum:OCSPNum:TLSNum */

    if( listDefault.size() >= 6 )
    {
        int nPort = listDefault.at(0).toInt();
        bool bTLS = listDefault.at(1).toInt();
        bool bNeedSign = listDefault.at(2).toInt();
        int nCANum = listDefault.at(3).toInt();
        int nOCSPNum = listDefault.at(4).toInt();
        int nTLSNum = listDefault.at(5).toInt();

        if( nPort > 0 ) mPortText->setText( QString("%1").arg(nPort));
        mTLSCheck->setChecked( bTLS );
        mNeedSignCheck->setChecked( bNeedSign );
        if( nCANum > 0 ) mCANumText->setText( QString("%1").arg( nCANum ));
        if( nOCSPNum > 0 ) mNumText->setText( QString("%1").arg( nOCSPNum ));
        if( nTLSNum > 0 ) mTLSNumText->setText( QString("%1").arg( nTLSNum ));

        mSetDefaultCheck->setChecked(true);
    }

    checkTLS();
}

QString OCSPServiceDlg::getDefault()
{
    QSettings settings;
    QString strDefault;

    settings.beginGroup( kSettingBer );
    strDefault = settings.value( kOCSPDefault ).toString();
    settings.endGroup();

    return strDefault;
}

void OCSPServiceDlg::setDefault( const QString strDefault )
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kOCSPDefault, strDefault );
    settings.endGroup();
}

void OCSPServiceDlg::clickStart()
{
    int ret = 0;
    BIN binCA = {0,0};
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};
    BIN binTLSCert = {0,0};
    BIN binTLSPriKey = {0,0};

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    QString strPort = mPortText->text();
    int nPort = -1;

    if( ocsp_srv_ != nullptr )
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

    CertRec caRec;
    int nCANum = mCANumText->text().toInt();
    int nTLSNum = -1;

    ret = dbMgr->getCertRec( nCANum, caRec );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get CA certificate" ), this );
        return;
    }

    int nNum = mNumText->text().toInt();
    bool bP11 = false;

    CertRec certRec;
    KeyPairRec keyPair;

    ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get OCSP certificate" ), this );
        return;
    }

    ret = dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get OCSP private key" ), this );
        return;
    }

    bP11 = isPKCS11Private( keyPair.getAlg() );

    JS_BIN_decodeHex( caRec.getCert().toStdString().c_str(), &binCA );
    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    manApplet->getPriKey( keyPair.getPrivateKey(), &binPriKey );

    if( mTLSCheck->isChecked() == true )
    {
        nTLSNum = mTLSNumText->text().toInt();

        int ret = dbMgr->getCertRec( nTLSNum, certRec );
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

    if( ocsp_srv_ ) delete ocsp_srv_;
    ocsp_srv_ = new OCSPServer;
    nPort = strPort.toInt();
    ocsp_srv_->setNeedSign( mNeedSignCheck->isChecked() );
    ocsp_srv_->setLogEdit( mLogText );
    ocsp_srv_->setCACert( &binCA );
    ocsp_srv_->setOCSPCert( &binCert );
    ocsp_srv_->setOCSPPriKey( &binPriKey, bP11 );

    if( mTLSCheck->isChecked() == true )
    {
        ocsp_srv_->setTLS( &binTLSCert, &binTLSPriKey );
    }

    ocsp_srv_->startServer( nPort );
    mStartBtn->setStyleSheet( kColorBackGreen );

    if( mSetDefaultCheck->isChecked() == true )
    {
        /* Port:TLS:NeedSign:CANum:OCSPNum:TLSNum */
        QString strDefault = QString( "%1:%2:%3:%4:%5:%6" )
            .arg( nPort )
            .arg( mTLSCheck->isChecked() )
            .arg( mNeedSignCheck->isChecked() )
            .arg(nCANum)
            .arg( nNum )
            .arg( nTLSNum );

        setDefault( strDefault );
    }
    else
    {
        setDefault( "" );
    }

end :
    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPriKey );
    JS_BIN_reset( &binTLSCert );
    JS_BIN_reset( &binTLSPriKey );
}

void OCSPServiceDlg::clickStop()
{
    mStartBtn->setStyleSheet( "" );
    if( ocsp_srv_ == nullptr ) return;

    ocsp_srv_->deleteLater();
    ocsp_srv_ = nullptr;
}

void OCSPServiceDlg::clickLogClear()
{
    mLogText->clear();
}

void OCSPServiceDlg::clickCASelect()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select CA certificate" ));
    caMan.setMode( CAManModeSelectCACert );

    if( caMan.exec() == QDialog::Accepted )
    {
        mCANumText->setText(QString("%1").arg( caMan.getNum() ));
    }
}

void OCSPServiceDlg::clickCAView()
{
    int num = mCANumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void OCSPServiceDlg::changeCANum()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int nNum = mCANumText->text().toInt();

    CertRec certRec;
    KeyPairRec keyPair;

    int ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        mCANumText->clear();
        return;
    }

    mCANameText->setText( certRec.getSubjectDN() );

    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mCAInfoText->setText( keyPair.getDesc() );
}

void OCSPServiceDlg::clickSelect()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select OCSP server certificate" ));
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

void OCSPServiceDlg::checkTLS()
{
    mTLSGroup->setEnabled( mTLSCheck->isChecked() );
}

void OCSPServiceDlg::clickTLSSelect()
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

void OCSPServiceDlg::clickTLSView()
{
    int num = mTLSNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void OCSPServiceDlg::changeTLSNum()
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
