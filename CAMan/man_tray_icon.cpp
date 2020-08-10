#include <QTime>

#include "man_tray_icon.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "server_status_service.h"

const int kRefreshInterval = 3 * 60 * 1000; // 3 min

ManTrayIcon::ManTrayIcon( QObject *parent )
{
    QIcon icon( ":/images/caman.png" );
    setIcon( icon );

    refresh_timer_ = new QTimer(this);
    connect( refresh_timer_, SIGNAL(timeout()), this, SLOT(refreshTrayIcon()));

    createContextMenu();
}


void ManTrayIcon::start()
{
    show();
    refresh_timer_->start( kRefreshInterval );
}

void ManTrayIcon::createContextMenu()
{
    context_menu_ = new QMenu(NULL);
    context_menu_->addAction( tr("Settings"), this, &ManTrayIcon::settings );
    context_menu_->addAction( tr("ServerStatus"), this, &ManTrayIcon::serverStatus );
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

void ManTrayIcon::serverStatus()
{
    manApplet->mainWindow()->serverStatus();
}

void ManTrayIcon::refreshTrayIcon()
{
    if( !ServerStatusService::instance()->allServersConnected() )
    {
        showMessage( "CAMan", tr("Some servers are not connected"), QSystemTrayIcon::Warning, 10000 );
    }
}
