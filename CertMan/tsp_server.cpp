#include <QDebug>
#include <QtNetwork/QtNetwork>
#include "tsp_server.h"
#include "work_thread.h"
#include "man_applet.h"

TSPServer::TSPServer( QObject *parent ) :
    QTcpServer(parent)
{

}

void TSPServer::startServer()
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

void TSPServer::incomingConnection( qintptr socketDescriptor )
{
    qDebug() << socketDescriptor << " Connecting...";

    WorkThread *thread = new WorkThread( socketDescriptor, this );

    connect( thread, SIGNAL(finished()), thread, SLOT(deleteLater()) );

    thread->start();
}
