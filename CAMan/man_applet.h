#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;
class ManTrayIcon;
class SettingsMgr;
class AboutDlg;


class ManApplet : public QObject
{
    Q_OBJECT
public:
    ManApplet(QObject *parent = nullptr);
    ~ManApplet();

    void start();
    void log( const QString strLog, QColor cr = QColor(00,00,00) );

    MainWindow* mainWindow() { return main_win_; };
    ManTrayIcon* trayIcon() { return tray_icon_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };

    void* P11CTX() { return p11_ctx_; };

    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();
    void restartApp();
    QString getSetPath();
    bool isPRO() { return is_pro_; };

private:
    int loadPKCS11();

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    ManTrayIcon* tray_icon_;
    SettingsMgr* settings_mgr_;

    void*       p11_ctx_;

    bool is_pro_;
    bool in_exit_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
