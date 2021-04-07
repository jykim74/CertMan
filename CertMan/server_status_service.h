#ifndef SERVERSTATUSSERVICE_H
#define SERVERSTATUSSERVICE_H

#include "singleton.h"
#include <QTimer>
#include <QUrl>
#include <QHash>
#include <QString>

class SettingsMgr;

class ServerStatus {
public:
    ServerStatus() {}
    ServerStatus(const QUrl& url, bool connected ) :
        url(url),
        connected(connected) {}

    QUrl url;
    bool connected;
};

class ServerStatusService : public QObject
{
    Q_OBJECT
    SINGLETON_DEFINE(ServerStatusService)
public:
    void start( SettingsMgr *mgr );
    void stop();
    void loadServerList(SettingsMgr *mgr);

    const QHash<QString, ServerStatus> statuses() { return statuses_; };
    const QList<ServerStatus> values() const { return statuses_.values(); };

    bool allServersConnected() const;
    bool allServersDisconnected() const;

public slots:
    void refresh();

private:

    Q_DISABLE_COPY(ServerStatusService)
    ServerStatusService(QObject *parent=nullptr);

    void pingServer( const QString key );

    QTimer  *refresh_timer_;
    QHash<QString, ServerStatus> statuses_;
};

#endif // SERVERSTATUSSERVICE_H
