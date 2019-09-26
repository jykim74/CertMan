#include "man_applet.h"
#include "mainwindow.h"

ManApplet *manApplet;

ManApplet::ManApplet(QObject *parent) : QObject(parent)
{
    main_win_ = new MainWindow;
}

void ManApplet::start()
{
    main_win_->show();
}
