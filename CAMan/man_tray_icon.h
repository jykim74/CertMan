#ifndef MAN_TRAY_ICON_H
#define MAN_TRAY_ICON_H

#include <QMenu>
#include <QSystemTrayIcon>


class ManTrayIcon : public QSystemTrayIcon
{
    Q_OBJECT

public:
    ManTrayIcon();

    void start();

private:
    void createContextMenu();

private slots :
    void quit();
    void settings();

private:
    QMenu   *context_menu_;
};

#endif // MAN_TRAN_ICON_H
