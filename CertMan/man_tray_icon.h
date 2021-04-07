#ifndef MAN_TRAY_ICON_H
#define MAN_TRAY_ICON_H

#include <QMenu>
#include <QSystemTrayIcon>


class ManTrayIcon : public QSystemTrayIcon
{
    Q_OBJECT

public:
    ManTrayIcon( QObject *parent = 0);

    void start();

private:
    void createContextMenu();

private slots :
    void quit();
    void settings();
    void serverStatus();
    void refreshTrayIcon();

private:
    QMenu   *context_menu_;
    QTimer  *refresh_timer_;
};

#endif // MAN_TRAN_ICON_H
