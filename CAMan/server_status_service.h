#ifndef SERVERSTATUSSERVICE_H
#define SERVERSTATUSSERVICE_H

#include "singleton.h"
#include <QTimer>
#include <QUrl>
#include <QHash>
#include <QString>

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
    void start();
    void stop();

    const QList<ServerStatus> statuses() const { return statuses_.values(); }

public slots:
    void refresh();

private:
    Q_DISABLE_COPY(ServerStatusService)
    ServerStatusService(QObject *parent=nullptr);

    void pingServer( const QUrl& url );

    QTimer  *refresh_timer_;
    QHash<QString, ServerStatus> statuses_;
};

#endif // SERVERSTATUSSERVICE_H
