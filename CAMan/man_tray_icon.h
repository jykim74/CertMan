#ifndef MAN_TRAY_ICON_H
#define MAN_TRAY_ICON_H

#include <QSystemTrayIcon>


class ManTrayIcon : public QSystemTrayIcon
{
    Q_OBJECT

public:
    ManTrayIcon();

    void start();
};

#endif // MAN_TRAN_ICON_H
