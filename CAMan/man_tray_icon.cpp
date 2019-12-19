#include "man_tray_icon.h"
#include "mainwindow.h"
#include "man_applet.h"

ManTrayIcon::ManTrayIcon()
{
    QIcon icon( ":/images/caman.png" );
    setIcon( icon );

    createContextMenu();
}


void ManTrayIcon::start()
{
    show();
}

void ManTrayIcon::createContextMenu()
{
    context_menu_ = new QMenu(NULL);
    context_menu_->addAction( tr("Settings"), this, &ManTrayIcon::settings );
    context_menu_->addSeparator();
    context_menu_->addAction( tr("Quit"), this, &ManTrayIcon::quit);

    setContextMenu( context_menu_ );
}

void ManTrayIcon::quit()
{
    manApplet->mainWindow()->quit();
}

void ManTrayIcon::settings()
{
    manApplet->mainWindow()->settings();
}
