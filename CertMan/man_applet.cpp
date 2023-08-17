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
#include "get_ldap_dlg.h"
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

ManApplet *manApplet;

ManApplet::ManApplet(QObject *parent) : QObject(parent)
{
#ifdef JS_PRO
    is_pro_ = true;
#else
    is_pro_ = false;
#endif


    tray_icon_ = new ManTrayIcon;
    settings_mgr_ = new SettingsMgr;
    db_mgr_ = new DBMgr;
//    db_mgr_ = NULL;

    in_exit_ = false;
    is_license_ = false;

    memset( &license_info_, 0x00, sizeof(license_info_));

    is_passwd_ = false;
    //memset( &pass_key_, 0x00, sizeof(pass_key_));
    pri_passwd_.clear();

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->start();
    }
#endif

    loadPKCS11();
    if( settings_mgr_->serverStatus() )
        ServerStatusService::instance()->start(settings_mgr_);
}

ManApplet::~ManApplet()
{
//    delete main_win_;

#ifdef _AUTO_UPDATE
    AutoUpdateService::instance()->stop();
#endif

}

int ManApplet::loadPKCS11()
{
    bool bval = settings_mgr_->PKCS11Use();

    if( bval )
    {
        QString strLibPath = settings_mgr_->PKCS11LibraryPath();
        int rv = JS_PKCS11_LoadLibrary( (JP11_CTX **)&p11_ctx_, strLibPath.toStdString().c_str() );
        if( rv == CKR_OK ) JS_PKCS11_Initialize( (JP11_CTX *)p11_ctx_, NULL );
    }
    else
    {
        p11_ctx_ = NULL;
    }
}

void ManApplet::start()
{
    checkLicense();

    main_win_ = new MainWindow;
    main_win_->show();
    tray_icon_->show();

    if( isLicense() )
    {
        if( settingsMgr()->showLogTab() )
            main_win_->logView(true);
    }
    else
    {
        info( "The CertMan is not licensed" );
    }

    QString strVersion = STRINGIZE(CERTMAN_VERSION);
    log( "======================================================");

    if( manApplet->isPRO() )
        log( QString( "== Start CertMan PRO Version: %1" ).arg( strVersion ));
    else
        log( QString( "== Start CertMan Version: %1" ).arg( strVersion ));

    log( "======================================================");
}

void ManApplet::setCurFile( const QString& strFile )
{
    cur_file_ = strFile;
}

QString ManApplet::curFolder()
{
    if( cur_file_.length() < 1 ) return ".";

    QFileInfo file;
    file.setFile( cur_file_ );
    QDir folder = file.dir();

    return folder.path();
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

    JS_BIN_decodeHex( strLicense.toStdString().c_str(), &binEncLCN );
    if( binEncLCN.nLen > 0 ) JS_LCN_dec( strEmail.toStdString().c_str(), &binEncLCN, &binLCN );

    ret = JS_LCN_ParseBIN( &binLCN, &license_info_ );
    if( ret != 0 )
    {
        QFile resFile( ":/certman_license.lcn" );
        resFile.open(QIODevice::ReadOnly);
        QByteArray data = resFile.readAll();
        resFile.close();

        if( data.size() != sizeof( JS_LICENSE_INFO ) ) goto end;

        memcpy( &license_info_, data.data(), data.size() );
    }

    ntp_t = JS_NET_clientNTP( JS_NTP_SERVER, JS_NTP_PORT, 2 );
    if( ntp_t <= 0 ) ntp_t = time(NULL);

    ret = JS_LCN_IsValid( &license_info_, JS_LCN_PRODUCT_CERTMAN_NAME, NULL, ntp_t );

    if( ret == JS_LCN_VALID )
        is_license_ = true;

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
    if( in_exit_ || QCoreApplication::closingDown() )
        return;

    in_exit_ = true;


    QStringList args = QApplication::arguments();
    args.removeFirst();

    QProcess::startDetached(QApplication::applicationFilePath(), args);
    QCoreApplication::quit();
}

QString ManApplet::getBrand()
{
    if( is_license_ )
        return QString::fromUtf8( "CertMan" );
    else
        return QString::fromUtf8( "CertManLite" );
}

QString ManApplet::getSetPath()
{
    bool bSavePath = settings_mgr_->saveDBPath();
    QString strPath = QDir::currentPath();

    if( bSavePath )
    {
        QSettings settings;
        settings.beginGroup("mainwindow");
        strPath = settings.value( "dbPath", "" ).toString();
        settings.endGroup();
    }

    return strPath;
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

QString ManApplet::getEncPriHex( const BIN *pPri )
{
    int ret = 0;
    BIN binEnc = {0,0};
//    BIN binIV = {0,0};
    int nKeyType = -1;
    QString strHex;

    if( is_passwd_ == false ) return "";
    if( pPri == NULL || pPri->nLen <= 0 ) return "";

    //ret = JS_PKI_encryptData( "aes-128-cbc", 1, pPri, &binIV, &pass_key_, &binEnc );

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
    BIN binEnc = {0,0};
//    BIN binIV = {0,0};

    if( is_passwd_ == false ) return -1;

    if( strEncPriHex.length() < 1 ) return -2;

    JS_BIN_decodeHex( strEncPriHex.toStdString().c_str(), &binEnc );
//    ret = JS_PKI_decryptData( "aes-128-cbc", 1, &binEnc, &binIV, &pass_key_, pDecPri );
    ret = JS_PKI_decryptPrivateKey( pri_passwd_.toStdString().c_str(), &binEnc, NULL, pDecPri );

    JS_BIN_reset( &binEnc );

    return ret;
}
