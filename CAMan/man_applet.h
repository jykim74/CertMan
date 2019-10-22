#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;
class ManTrayIcon;
class SettingsMgr;

class ManApplet : public QObject
{
    Q_OBJECT
public:
    explicit ManApplet(QObject *parent = nullptr);
    void start();

    MainWindow* mainWindow() { return main_win_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };

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

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    ManTrayIcon* tray_icon_;
    SettingsMgr* settings_mgr_;

    bool in_exit_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
