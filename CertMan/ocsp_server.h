#ifndef OCSP_SERVER_H
#define OCSP_SERVER_H

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>

class OCSPServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit OCSPServer( QObject *parent = nullptr );
    void startServer();

public slots:

private:

protected:
    void incomingConnection( qintptr socketDescriptor );
};

#endif // OCSP_SERVER_H
