#include "server_status_service.h"
#include "settings_mgr.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "js_http.h"
#include "js_net.h"


SINGLETON_IMPL(ServerStatusService)

const static int kRefreshInterval = 1 * 60 * 1000; // 1 min

ServerStatusService::ServerStatusService(QObject *parent)
{
    refresh_timer_ = new QTimer(this);
    connect( refresh_timer_, SIGNAL(timeout()), this, SLOT(refresh()));
}

void ServerStatusService::start( SettingsMgr *mgr )
{
    refresh_timer_->start( kRefreshInterval );
    loadServerList(mgr);
    refresh();
}

void ServerStatusService::stop()
{
    refresh_timer_->stop();
}

void ServerStatusService::loadServerList(SettingsMgr *mgr)
{
    if( mgr == NULL )
    {
        fprintf( stderr, "settings mgr is null\n" );
    }

    if( mgr->KMIPUse() )
    {
        QString strKMI = "http://";
        strKMI += mgr->KMIPHost();
        strKMI += ":";
        strKMI += mgr->KMIPPort();

        QUrl url( strKMI );

        statuses_["KMS"] = ServerStatus( QUrl(strKMI), false );
    }

    if( mgr->CMPUse() )
    {
        statuses_["CMP"] = ServerStatus( QUrl(mgr->CMPURI()), false );
    }

    if( mgr->OCSPUse() )
    {
        statuses_["OCSP"] = ServerStatus( QUrl(mgr->OCSPURI()), false );
    }

    if( mgr->TSPUse() )
    {
        statuses_["TSP"] = ServerStatus( QUrl(mgr->TSPURI()), false );
    }

    if( mgr->REGUse() )
    {
        statuses_["REG"] = ServerStatus( QUrl(mgr->REGURI()), false );
    }
}

bool ServerStatusService::allServersConnected() const
{
    foreach( const ServerStatus& status, values() )
    {
        if( !status.connected ) {
            return  false;
        }
    }

    return true;
}

bool ServerStatusService::allServersDisconnected() const
{
    foreach( const ServerStatus& status, values() )
    {
        if( status.connected ) {
            return  false;
        }
    }

    return true;
}

void ServerStatusService::refresh()
{
    QList<QString> keys = statuses_.keys();

    for( int i =0; i < keys.size(); i++ )
    {
        QString key = keys.value(i);
        ServerStatus srvStatus = statuses_[key];
        pingServer( key );
    }
}

void ServerStatusService::pingServer(const QString key )
{
    int ret = 0;
    bool res = true;
    QString strURL = statuses_[key].url.toString();

    if( key == "KMS" )
    {
        QUrl url( strURL );
        QString strHost = url.host();
        int nPort = url.port();

        ret = JS_NET_connect( strHost.toStdString().c_str(), nPort );
        if( ret > 0 )
        {
            JS_NET_close( ret );
            ret = 0;
        }
        else
        {
            ret = -1;
        }

    }
    else
    {
        strURL += "/PING";
        ret = JS_HTTP_ping( strURL.toStdString().c_str() );
    }

    if( ret == 0 )
        res = true;
    else
    {
        res = false;
    }

    statuses_[key].connected = res;

}
