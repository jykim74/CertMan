#include "js_gen.h"

#include "remote_db_dlg.h"
#include "commons.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "login_dlg.h"
#include "man_tray_icon.h"
#include "mainwindow.h"
#include "settings_mgr.h"

RemoteDBDlg::RemoteDBDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();
}

RemoteDBDlg::~RemoteDBDlg()
{

}

void RemoteDBDlg::initialize()
{
    mDBTypeCombo->addItems( kRemoteDBList );
    mConnectBtn->setDefault(true);

    if( manApplet->settingsMgr()->saveRemoteInfo() )
    {
        QString strInfo = manApplet->settingsMgr()->remoteInfo();
        QStringList infoList = strInfo.split( ":" );

        if( infoList.size() >= 4 )
        {
            mDBTypeCombo->setCurrentIndex( infoList.at(0).toInt() );
            mHostnameText->setText( infoList.at(1) );
            mDBNameText->setText( infoList.at(2) );
            mUsernameText->setText( infoList.at(3) );
        }
    }

    if( mHostnameText->text().length() < 1 ) mHostnameText->setText( "localhost" );
    if( mDBNameText->text().length() < 1 ) mDBNameText->setText( "certman" );

    mConnectBtn->setFocus();
}

void RemoteDBDlg::clickClear()
{
    mHostnameText->clear();
    mUsernameText->clear();
    mPasswordText->clear();
    mDBNameText->clear();
}

void RemoteDBDlg::clickConnect()
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    dbMgr->close();

    QString strType;
    int nType = mDBTypeCombo->currentIndex();

    if( nType == 0 )
        strType = "QMYSQL";
    else if( nType == 1 )
        strType = "QPSQL";
    else if( nType == 2 )
        strType = "QODBC";

    QString strHost = mHostnameText->text();
    QString strUserName = mUsernameText->text();
    QString strPasswd = mPasswordText->text();
    QString strDBName = mDBNameText->text();

    ret = dbMgr->remoteOpen( strType, strHost, strUserName, strPasswd, strDBName );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database"), this );
        return;
    }

    QString strConf;

    dbMgr->getConfigValue( JS_GEN_KIND_CERTMAN, "Passwd", strConf );

    if( strConf.length() > 1 )
    {
        LoginDlg loginDlg;
        if( loginDlg.exec() != QDialog::Accepted )
            return;

        QString strPasswd = loginDlg.getPasswd();

        QString strHMAC = getPasswdHMAC( strPasswd );

        if( strConf != strHMAC )
        {
            manApplet->warningBox( tr("Password is wrong"), this );
            dbMgr->close();
            return;
        }

        manApplet->setPasswdKey( strPasswd );
    }

    manApplet->mainWindow()->createTreeMenu();

    if( manApplet->isPRO() == true )
    {
        if( manApplet->trayIcon()->supportsMessages() )
            manApplet->trayIcon()->showMessage( "CertMan", tr("DB file is opened"), QSystemTrayIcon::Information, 10000 );
    }

    QString strTitle = QString( "RemoteDB[%1] : %2").arg( strType ).arg( strHost );
    manApplet->mainWindow()->setTitle( strTitle );

    if( manApplet->settingsMgr()->saveRemoteInfo() == true )
    {
        QString strInfo = QString( "%1:%2:%3:%4" )
                .arg( mDBTypeCombo->currentIndex() )
                .arg( mHostnameText->text() )
                .arg( mDBNameText->text() )
                .arg( mUsernameText->text() );

        manApplet->settingsMgr()->setRemoteInfo( strInfo );
    }

    QDialog::accept();
}
