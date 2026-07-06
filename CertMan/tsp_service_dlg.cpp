#include <QSettings>

#include "js_gen.h"
#include "js_pki.h"
#include "js_tsp.h"

#include "tsp_service_dlg.h"
#include "tsp_server.h"

#include "man_applet.h"
#include "ca_man_dlg.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"
#include "commons.h"

const QString kTSPDefault = "TSPDefault";

TSPServiceDlg::TSPServiceDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    tsp_srv_ = nullptr;

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mStopBtn, SIGNAL(clicked()), this, SLOT(clickStop()));

    connect( mTLSCheck, SIGNAL(clicked()), this, SLOT(checkTLS()));
    connect( mLogClearBtn, SIGNAL(clicked()), this, SLOT(clickLogClear()));
    connect( mSelectBtn, SIGNAL(clicked()), this, SLOT(clickSelect()));
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView()));
    connect( mNumText, SIGNAL(textChanged(QString)), this, SLOT(changeNum()));
    connect( mTLSSelectBtn, SIGNAL(clicked()), this, SLOT(clickTLSSelect()));
    connect( mTLSViewBtn, SIGNAL(clicked()), this, SLOT(clickTLSView()));
    connect( mTLSNumText, SIGNAL(textChanged(QString)), this, SLOT(changeTLSNum()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

TSPServiceDlg::~TSPServiceDlg()
{
    if( tsp_srv_ ) delete tsp_srv_;
}

void TSPServiceDlg::initUI()
{
    mPortText->setText( QString("%1").arg( JS_TSP_PORT ));
}

void TSPServiceDlg::initialize()
{
    QString strDefault = getDefault();
    QStringList listDefault;

    if( strDefault.length() > 4 ) listDefault = strDefault.split(":");

    /* Port:TLS:TSPNum:TLSNum */

    if( listDefault.size() >= 4 )
    {
        int nPort = listDefault.at(0).toInt();
        bool bTLS = listDefault.at(1).toInt();
        int nNum = listDefault.at(2).toInt();
        int nTLSNum = listDefault.at(3).toInt();

        if( nPort > 0 ) mPortText->setText( QString("%1").arg(nPort));
        mTLSCheck->setChecked( bTLS );
        if( nNum > 0 ) mNumText->setText( QString("%1").arg( nNum ));
        if( nTLSNum > 0 ) mTLSNumText->setText( QString("%1").arg( nTLSNum ));

        mSetDefaultCheck->setChecked( true );
    }

    checkTLS();
}

QString TSPServiceDlg::getDefault()
{
    QSettings settings;
    QString strDefault;

    settings.beginGroup( kSettingBer );
    strDefault = settings.value( kTSPDefault ).toString();
    settings.endGroup();

    return strDefault;
}

void TSPServiceDlg::setDefault( const QString strDefault )
{
    QSettings settings;
    settings.beginGroup( kSettingBer );
    settings.setValue( kTSPDefault, strDefault );
    settings.endGroup();
}

void TSPServiceDlg::checkTLS()
{
    mTLSGroup->setEnabled( mTLSCheck->isChecked() );
}

void TSPServiceDlg::clickStart()
{
    BIN binCert = {0,0};
    BIN binPriKey = {0,0};
    BIN binTLSCert = {0,0};
    BIN binTLSPriKey = {0,0};

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    QString strPort = mPortText->text();
    bool bP11 = false;
    int nPort = strPort.toInt();

    if( tsp_srv_ != nullptr )
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

    int nNum = mNumText->text().toInt();
    int nTLSNum = -1;

    CertRec certRec;
    KeyPairRec keyPair;

    int ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get TSP certificate" ), this );
        return;
    }

    ret = dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get TSP private key" ), this );
        return;
    }

    bP11 = isPKCS11Private( keyPair.getAlg() );

    if( tsp_srv_ ) delete tsp_srv_;

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

    tsp_srv_ = new TSPServer;
    tsp_srv_->setLogEdit( mLogText );
    tsp_srv_->setTSPCert( &binCert );
    tsp_srv_->setTSPPriKey( &binPriKey, bP11 );

    if( mTLSCheck->isChecked() == true )
    {
        if( binTLSCert.nLen < 1 || binTLSPriKey.nLen < 1 )
        {
            manApplet->warningBox( tr( "Failed to configure TLS certificate and private key." ), this );
            goto end;
        }

        tsp_srv_->setTLS( &binTLSCert, &binTLSPriKey );
    }

    tsp_srv_->startServer( nPort );
    mStartBtn->setStyleSheet( kColorBackGreen );

    if( mSetDefaultCheck->isChecked() == true )
    {
        /* Port:TLS:TSPNum:TLSNum */
        QString strDefault = QString( "%1:%2:%3:%4" )
                                 .arg( nPort )
                                 .arg( mTLSCheck->isChecked() )
                                 .arg(nNum)
                                 .arg( nTLSNum );

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

void TSPServiceDlg::clickStop()
{
    mStartBtn->setStyleSheet( "" );
    if( tsp_srv_ == nullptr ) return;

    tsp_srv_->deleteLater();
    tsp_srv_ = nullptr;
}

void TSPServiceDlg::clickLogClear()
{
    mLogText->clear();
}

void TSPServiceDlg::clickSelect()
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

void TSPServiceDlg::clickView()
{
    int num = mNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void TSPServiceDlg::changeNum()
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

void TSPServiceDlg::clickTLSSelect()
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

void TSPServiceDlg::clickTLSView()
{
    int num = mTLSNumText->text().toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void TSPServiceDlg::changeTLSNum()
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
