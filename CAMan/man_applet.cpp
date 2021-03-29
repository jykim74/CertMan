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

    in_exit_ = false;

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
        if( rv == CKR_OK ) JS_PKCS11_Initialize( (JP11_CTX *)p11_ctx_ );
    }
    else
    {
        p11_ctx_ = NULL;
    }
}

void ManApplet::start()
{
    main_win_ = new MainWindow;
    main_win_->show();
    tray_icon_->show();
}

void ManApplet::log( const QString strLog, QColor cr )
{
    main_win_->log( strLog, cr );
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
    return QString::fromUtf8( "CAMan" );
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
