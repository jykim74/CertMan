#include "man_applet.h"
#include "mainwindow.h"
#include "man_tray_icon.h"

ManApplet *manApplet;

ManApplet::ManApplet(QObject *parent) : QObject(parent)
{
    main_win_ = new MainWindow;
    tray_icon_ = new ManTrayIcon;
}

void ManApplet::start()
{
    main_win_->show();
    tray_icon_->show();
}
