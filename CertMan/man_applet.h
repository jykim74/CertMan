/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>
#include "js_bin.h"
#include "js_license.h"


class MainWindow;
class ManTrayIcon;
class SettingsMgr;
class DBMgr;
class AboutDlg;


class ManApplet : public QObject
{
    Q_OBJECT
public:
    ManApplet(QObject *parent = nullptr);
    ~ManApplet();

    void start();
    int checkLicense();
    JS_LICENSE_INFO& LicenseInfo() { return license_info_; };

    void log( const QString strLog, QColor cr = QColor(00,00,00) );
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(00,00,00) );

    MainWindow* mainWindow() { return main_win_; };
    ManTrayIcon* trayIcon() { return tray_icon_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };
    DBMgr* dbMgr() { return db_mgr_; };

    void* P11CTX() { return p11_ctx_; };

    void messageBox(const QString& msg, QWidget *parent);
    void warningBox(const QString& msg, QWidget *parent);
    bool yesOrNoBox(const QString& msg, QWidget *parent, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    void messageLog( const QString strLog, QWidget *parent );
    void warnLog( const QString strLog, QWidget *parent );
    void formatWarn( int rv, QWidget *parent );

    int getPriKey( const QString strHexPri, BIN *pPri );


    static QString getBrand();
    void restartApp();
    void exitApp( int nNum = 0 );

    QString getDBPath();
    void setDBPath( const QString strPath );

    bool isPRO() { return is_pro_; };
    bool isDBOpen();
    bool isLicense() { return  is_license_; };

    bool isPasswd() { return is_passwd_; };
    const QString priPasswd() { return pri_passwd_; };
    void setPasswdKey( const QString strPasswd );
    void clearPasswdKey();

    QString getEncPriHex( const BIN *pPri );
    int getDecPriBIN( const QString& strEncPriHex, BIN *pDecPri );
    int getDecPriBIN( const QString& strPasswd, const QString& strEncPriHex, BIN *pDecPri );

    QString curFilePath( const QString strPath = "" );
    QString curPath( const QString strPath = "" );

    int loignRegServer( QString& strToken );

    QString findFile( QWidget *parent, int nType, const QString strPath, bool bSave = true );
    QString findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected, bool bSave = true );
    QString findSaveFile( QWidget *parent, int nType, const QString strPath, bool bSave = true );
    QString findSaveFile( QWidget *parent, const QString strFilter, const QString strPath, bool bSave = true );
    QString findFolder( QWidget *parent, const QString strPath, bool bSave = true );

private:
    int loadPKCS11();

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    ManTrayIcon* tray_icon_;
    SettingsMgr* settings_mgr_;
    DBMgr*      db_mgr_;

    void*       p11_ctx_;

    bool is_pro_;
    bool is_license_;
    JS_LICENSE_INFO license_info_;

    bool is_passwd_;
    QString pri_passwd_;
    QString cur_file_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
