#include "server_status_service.h"

static QStringList sServerList = {
    "http://localhost:9000",
    "http://localhost:9010",
    "http://localhost:9020",
    "http://localhost:9030"
};

SINGLETON_IMPL(ServerStatusService)

ServerStatusService::ServerStatusService(QObject *parent)
{
    refresh_timer_ = new QTimer(this);

    refresh();

    connect( refresh_timer_, SIGNAL(timeout()), this, SLOT(refresh()));
}

void ServerStatusService::start()
{

}

void ServerStatusService::stop()
{
    refresh_timer_->stop();
}

void ServerStatusService::refresh()
{
    for( int i=0; i < sServerList.size(); i++ )
    {
        const QUrl& url = sServerList.at(i);

        pingServer(url);
    }
}

void ServerStatusService::pingServer(const QUrl &url)
{
    bool res = true;

    QString strKey = QString("%1:%2").arg( url.host()).arg( url.port());

    statuses_[strKey] = ServerStatus( url, res );
}
