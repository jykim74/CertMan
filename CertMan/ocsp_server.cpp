#include <QDebug>
#include <QtNetwork/QtNetwork>
#include "ocsp_server.h"


OCSPServer::OCSPServer( QObject *parent ) :
    QTcpServer(parent)
{

}

void OCSPServer::startServer()
{
    int port = 9090;

    if( !this->listen( QHostAddress::Any, port) )
    {
        qDebug() << "Could not start server";
    }
    else
    {
        qDebug() << "Listening to port " << port << "...";
    }
}

void OCSPServer::incomingConnection( qintptr socketDescriptor )
{
    qDebug() << socketDescriptor << " Connecting...";
}
