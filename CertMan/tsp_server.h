#ifndef TSP_SERVER_H
#define TSP_SERVER_H

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>

class TSPServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit TSPServer( QObject *parent = nullptr );
    void startServer();

public slots:

private:

protected:
    void incomingConnection( qintptr socketDescriptor );
};

#endif // TSP_SERVER_H
