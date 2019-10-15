#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>

class MainWindow;
class ManTrayIcon;

class ManApplet : public QObject
{
    Q_OBJECT
public:
    explicit ManApplet(QObject *parent = nullptr);
    void start();

    MainWindow* mainWindow() { return main_win_; };

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    ManTrayIcon* tray_icon_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
