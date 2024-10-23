/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QPushButton>
#include <QProcess>
#include <QApplication>
#include <QSpacerItem>
#include <QGridLayout>

#include "man_applet.h"
#include "mainwindow.h"
#include "man_tray_icon.h"
#include "settings_dlg.h"
#include "settings_mgr.h"
#include "db_mgr.h"
#include "about_dlg.h"
#include "export_dlg.h"
#include "get_uri_dlg.h"
#include "import_dlg.h"
#include "make_cert_dlg.h"
#include "make_cert_profile_dlg.h"
#include "make_crl_dlg.h"
#include "make_crl_profile_dlg.h"
#include "make_req_dlg.h"
#include "new_key_dlg.h"
#include "pub_ldap_dlg.h"
#include "revoke_cert_dlg.h"
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"
#include "auto_update_service.h"
#include "user_dlg.h"
#include "signer_dlg.h"
#include "server_status_service.h"
#include "js_pkcs11.h"
#include "js_gen.h"
#include "commons.h"
#include "js_net.h"
#include "lcn_info_dlg.h"
#include "js_json_msg.h".h"
#include "js_http.h"
#include "js_error.h"

ManApplet *manApplet;

ManApplet::ManApplet(QObject *parent) : QObject(parent)
{
#ifdef JS_PRO
    is_pro_ = true;
#else
    is_pro_ = false;
#endif

    settings_mgr_ = new SettingsMgr;
    main_win_ = nullptr;
    tray_icon_ = nullptr;
    db_mgr_ = nullptr;
    p11_ctx_ = NULL;


    is_license_ = false;

    memset( &license_info_, 0x00, sizeof(license_info_));

    is_passwd_ = false;
    pri_passwd_.clear();
    cur_file_.clear();

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->start();
    }
#endif

    if( is_pro_ == true )
    {
        if( settings_mgr_->serverStatus() )
            ServerStatusService::instance()->start(settings_mgr_);
    }
}

ManApplet::~ManApplet()
{
#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif

    if( main_win_ != nullptr ) delete main_win_;
    if( tray_icon_ != nullptr ) delete tray_icon_;
    if( settings_mgr_ != nullptr ) delete settings_mgr_;
    if( db_mgr_ != nullptr ) delete db_mgr_;

    if( p11_ctx_ != NULL ) JS_PKCS11_ReleaseLibrry( (JP11_CTX **)&p11_ctx_ );
}

int ManApplet::loadPKCS11()
{
    int rv = 0;

    QString strLibPath = settings_mgr_->PKCS11LibraryPath();
    if( strLibPath.length() < 1) return -1;

    rv = JS_PKCS11_LoadLibrary( (JP11_CTX **)&p11_ctx_, strLibPath.toStdString().c_str() );
    if( rv != CKR_OK )
    {
        return rv;
    }

    rv = JS_PKCS11_Initialize( (JP11_CTX *)p11_ctx_, NULL );
    if( rv != CKR_OK )
    {
        if( p11_ctx_ ) JS_PKCS11_ReleaseLibrry( (JP11_CTX **)&p11_ctx_ );
    }

    if( rv == CKR_OK )
        manApplet->log( "Cryptoki library loaded successfully" );
    else
        manApplet->elog( QString("Failed to load Cryptoki library [%1]").arg(rv) );

    return rv;
}

void ManApplet::start()
{
    checkLicense();

    main_win_ = new MainWindow;
    main_win_->show();

    db_mgr_ = new DBMgr;

    if( is_pro_ == true )
    {
        tray_icon_ = new ManTrayIcon;
        tray_icon_->show();
    }

    if( isLicense() )
    {
        main_win_->useLog( settingsMgr()->getUseLogTab() );
    }
    else
    {
        info( "The CertMan is unlicensed" );
        time_t tLastTime = manApplet->settings_mgr_->getStopMessage();
        if( tLastTime > 0 )
        {
            time_t now_t = time(NULL);
            if( now_t > ( tLastTime + 7 * 86400 ) )
            {
                manApplet->settings_mgr_->setStopMessage( now_t );
                LCNInfoDlg lcnInfo;
                lcnInfo.setCurTab(1);
                lcnInfo.exec();
            }
        }
        else
        {
            LCNInfoDlg lcnInfo;
            lcnInfo.setCurTab(1);
            lcnInfo.exec();
        }
    }

    QString strVersion = STRINGIZE(CERTMAN_VERSION);
    log( "======================================================");

    if( manApplet->isPRO() )
        log( QString( "== Start CertMan PRO Version: %1" ).arg( strVersion ));
    else
        log( QString( "== Start CertMan Version: %1" ).arg( strVersion ));

    log( "======================================================");

    if( settings_mgr_->PKCS11Use() == true )
        loadPKCS11();
}

QString ManApplet::curFilePath( const QString strPath )
{
    if( strPath.length() > 1 )
    {
        cur_file_ = strPath;
    }
    else
    {
        if( cur_file_.length() < 1 )
            cur_file_ = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    }

    return cur_file_;
}

QString ManApplet::curPath( const QString strPath )
{
    if( strPath.length() > 1 )
    {
        cur_file_ = strPath;
    }
    else
    {
        if( cur_file_.length() < 1 )
            cur_file_ = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    }

    QFileInfo file;
    file.setFile( cur_file_ );
    QDir folder = file.dir();

    return folder.path();
}

int ManApplet::loignRegServer( QString& strToken )
{
    int ret = 0;
    int nStatus = 0;
    char *pReq = NULL;
    char *pRsp = NULL;

    JRegAdminLoginReq   sLoginReq;
    JRegAdminLoginRsp   sLoginRsp;

    if( settings_mgr_->REGUse() == false )
    {
        manApplet->elog( "There are no REG settings" );
        return -1;
    }

    QString strAdminName = settings_mgr_->REGAdminName();
    QString strPassword = settings_mgr_->REGPassword();

    QString strURL = settings_mgr_->REGURI();
    strURL += JS_REG_PATH_ADMIN_LOGIN;

    if( strAdminName.length() < 1 )
    {
        manApplet->elog( "There is no admin name" );
        return -1;
    }

    memset( &sLoginReq, 0x00, sizeof(sLoginReq));
    memset( &sLoginRsp, 0x00, sizeof(sLoginRsp));

    JS_JSON_setRegAdminLoginReq( &sLoginReq, strAdminName.toStdString().c_str(), strAdminName.toStdString().c_str() );

    JS_JSON_encodeRegAdminLoginReq( &sLoginReq, &pReq );

    ret = JS_HTTP_requestPost( strURL.toStdString().c_str(), "application/json", pReq, &nStatus, &pRsp );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to request HTTP post: %1 (ret:%2)" ).arg( strURL ).arg( ret ));
        goto end;
    }

    JS_JSON_decodeRegAdminLoginRsp( pRsp, &sLoginRsp );
    if( strcasecmp( sLoginRsp.pResCode, "0000" ) == 0 )
    {
        strToken = sLoginRsp.pToken;
        ret = 0;
    }
    else
    {
        manApplet->elog( QString( "Error ResCode: %1").arg( sLoginRsp.pResCode ));
        ret = -1;
    }

end :
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );
    JS_JSON_resetRegAdminLoginReq( &sLoginReq );
    JS_JSON_resetRegAdminLoginRsp( &sLoginRsp );

    return ret;
}

int ManApplet::checkLicense()
{
    int ret = 0;
    time_t ntp_t = 0;
    is_license_ = false;

    BIN binLCN = {0,0};
    BIN binEncLCN = {0,0};

    QString strEmail = settings_mgr_->getEmail();
    QString strLicense = settings_mgr_->getLicense();
    QString strSID = GetSystemID();

    if( is_pro_ == true )
    {
        is_license_ = true;
        return is_license_;
    }

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binEncLCN );
    if( binEncLCN.nLen > 0 ) JS_LCN_dec( strEmail.toStdString().c_str(), &binEncLCN, &binLCN );

    ret = JS_LCN_ParseBIN( &binLCN, &license_info_ );

#ifdef _USE_RC_LCN
    if( ret != 0 )
    {
        QFile resFile( ":/certman_license.lcn" );
        resFile.open(QIODevice::ReadOnly);
        QByteArray data = resFile.readAll();
        resFile.close();

        if( data.size() != sizeof( JS_LICENSE_INFO ) ) goto end;

        memcpy( &license_info_, data.data(), data.size() );
    }
#else
    if( ret != 0 ) goto end;
#endif

#ifdef USE_TIME_SRV
    ntp_t = JS_NET_clientNTP( JS_NTP_SERVER, JS_NTP_PORT, 2 );
#endif
    if( ntp_t <= 0 ) ntp_t = time(NULL);

    ret = JS_LCN_IsValid( &license_info_, strEmail.toStdString().c_str(), JS_LCN_PRODUCT_CERTMAN_NAME, strSID.toStdString().c_str(), ntp_t );

    if( ret == JSR_VALID )
    {
        is_license_ = true;
    }
    else
    {
        QString strMsg = tr( "License is invalid: %1" ).arg(ret);
        manApplet->warningBox( strMsg, nullptr );
    }

end :
    JS_BIN_reset( &binLCN );
    JS_BIN_reset( &binEncLCN );

    return is_license_;
}

void ManApplet::log( const QString strLog, QColor cr )
{
    main_win_->log( strLog, cr );
}

void ManApplet::elog( const QString strLog )
{
    main_win_->elog( strLog );
}

void ManApplet::info( const QString strLog, QColor cr )
{
    main_win_->info( strLog, cr );
}

void ManApplet::restartApp()
{
    if( QCoreApplication::closingDown() )
        return;

    QStringList args = QApplication::arguments();
    args.removeFirst();

    QProcess::startDetached(QApplication::applicationFilePath(), args);
    QCoreApplication::quit();
}

void ManApplet::exitApp( int nNum )
{
    if ( QCoreApplication::closingDown()) {
        return;
    }

    QCoreApplication::exit(nNum);
}


QString ManApplet::getBrand()
{
    return QString::fromUtf8( "CertMan" );
}

QString ManApplet::getDBPath()
{
    QString strPath;
    QSettings settings;

    settings.beginGroup("mainwindow");
    strPath = settings.value( "dbPath", "" ).toString();
    settings.endGroup();

    return strPath;
}

void ManApplet::setDBPath( const QString strPath )
{
    QSettings settings;
    settings.beginGroup("mainwindow");
    settings.setValue( "dbPath", strPath );
    settings.endGroup();
}

bool ManApplet::isDBOpen()
{
    if( db_mgr_ == NULL ) return false;
    return db_mgr_->isOpen();
}

void ManApplet::warningBox(const QString& msg, QWidget *parent)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Warning);
    box.addButton(tr("OK"), QMessageBox::YesRole);
    box.exec();

    if (!parent && main_win_) {
        main_win_->showWindow();
    }
    qWarning("%s", msg.toUtf8().data());
}

void ManApplet::messageBox(const QString& msg, QWidget *parent)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Information);
    box.addButton(tr("OK"), QMessageBox::YesRole);
    box.exec();
    qDebug("%s", msg.toUtf8().data());
}

bool ManApplet::yesOrNoBox(const QString& msg, QWidget *parent, bool default_val)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *no_btn = box.addButton(tr("No"), QMessageBox::NoRole);
    box.setDefaultButton(default_val ? yes_btn: no_btn);
    box.exec();

    return box.clickedButton() == yes_btn;
}

bool ManApplet::yesOrCancelBox(const QString& msg, QWidget *parent, bool default_yes)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *cancel_btn = box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    box.setDefaultButton(default_yes ? yes_btn: cancel_btn);
    box.exec();

    return box.clickedButton() == yes_btn;
}

void ManApplet::messageLog( const QString strLog, QWidget *parent )
{
    messageBox( strLog, parent );
    log( strLog );
}

void ManApplet::warnLog( const QString strLog, QWidget *parent )
{
    warningBox( strLog, parent );
    elog( strLog );
}

QMessageBox::StandardButton
ManApplet::yesNoCancelBox(const QString& msg, QWidget *parent, QMessageBox::StandardButton default_btn)
{
    QMessageBox box(parent ? parent : main_win_);
    box.setText(msg);
    box.setWindowTitle(getBrand());
    box.setIcon(QMessageBox::Question);
    QPushButton *yes_btn = box.addButton(tr("Yes"), QMessageBox::YesRole);
    QPushButton *no_btn = box.addButton(tr("No"), QMessageBox::NoRole);
    box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    box.setDefaultButton(default_btn);
    box.exec();

    QAbstractButton *btn = box.clickedButton();
    if (btn == yes_btn) {
        return QMessageBox::Yes;
    } else if (btn == no_btn) {
        return QMessageBox::No;
    }

    return QMessageBox::Cancel;
}

bool ManApplet::detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val)
{
    QMessageBox msgBox(QMessageBox::Question,
                       getBrand(),
                       msg,
                       QMessageBox::Yes | QMessageBox::No,
                       parent != 0 ? parent : main_win_);
    msgBox.setDetailedText(detailed_text);
    msgBox.setButtonText(QMessageBox::Yes, tr("Yes"));
    msgBox.setButtonText(QMessageBox::No, tr("No"));
    // Turns out the layout box in the QMessageBox is a grid
    // You can force the resize using a spacer this way:
    QSpacerItem* horizontalSpacer = new QSpacerItem(400, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);
    QGridLayout* layout = (QGridLayout*)msgBox.layout();
    layout->addItem(horizontalSpacer, layout->rowCount(), 0, 1, layout->columnCount());
    msgBox.setDefaultButton(default_val ? QMessageBox::Yes : QMessageBox::No);
    return msgBox.exec() == QMessageBox::Yes;
}

void ManApplet::setPasswdKey( const QString strPasswd )
{
    /*
    BIN binSalt = {0,0};

    JS_GEN_getHMACKey( &binSalt );
    JS_BIN_reset( &pass_key_ );
    JS_PKI_PBKDF2( strPasswd.toStdString().c_str(), &binSalt, 1024, "SHA256", 16, &pass_key_ );
    JS_BIN_reset( &binSalt );
    */
    pri_passwd_ = strPasswd;
    is_passwd_ = true;
}

void ManApplet::clearPasswdKey()
{
    pri_passwd_.clear();
    is_passwd_ = false;
}

QString ManApplet::getEncPriHex( const BIN *pPri )
{
    int ret = 0;
    BIN binEnc = {0,0};
    int nKeyType = -1;
    QString strHex;

    if( is_passwd_ == false ) return "";
    if( pPri == NULL || pPri->nLen <= 0 ) return "";

    nKeyType = JS_PKI_getPriKeyType( pPri );
    ret = JS_PKI_encryptPrivateKey( nKeyType, -1, pri_passwd_.toStdString().c_str(), pPri, NULL, &binEnc );
    if( ret != 0 ) goto end;

    strHex = getHexString( &binEnc );

end :
    JS_BIN_reset( &binEnc );

    return strHex;
}

int ManApplet::getDecPriBIN( const QString& strEncPriHex, BIN *pDecPri )
{
    int ret = 0;

    if( is_passwd_ == false ) return -1;
    ret = getDecPriBIN( pri_passwd_, strEncPriHex, pDecPri );

    return ret;
}

int ManApplet::getDecPriBIN( const QString& strPasswd, const QString& strEncPriHex, BIN *pDecPri )
{
    int ret = 0;
    BIN binEnc = {0,0};

    if( strPasswd.length() < 1 ) return -1;

    if( strEncPriHex.length() < 1 ) return -2;

    JS_BIN_decodeHex( strEncPriHex.toStdString().c_str(), &binEnc );
    ret = JS_PKI_decryptPrivateKey( strPasswd.toStdString().c_str(), &binEnc, NULL, pDecPri );

    JS_BIN_reset( &binEnc );

    return ret;
}
