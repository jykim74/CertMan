#include "work_thread.h"
#include <QtNetwork/QtNetwork>

WorkThread::WorkThread( qintptr ID, QObject *parent )
{
    this->socketDescriptor = ID;
}

void WorkThread::run()
{
    qDebug() << "Thread started";

    socket = new QTcpSocket();

    if( !socket->setSocketDescriptor(this->socketDescriptor) )
    {
        qDebug() << "setSocketDescriptor fail";
        emit error( socket->error() );
        return;
    }

    connect( socket, SIGNAL(readyRead()), this, SLOT(readyRead()), Qt::DirectConnection );
    connect( socket, SIGNAL(disconnected()), this, SLOT(disconnected()) );

    qDebug() << socketDescriptor << " Client connected";

    exec();
}

void WorkThread::readyRead()
{
    QByteArray Data = socket->readAll();

    qDebug() << "Data size : " << Data.size();

    QString strData = Data.data();

    qDebug() << socketDescriptor << " Data in: " << strData;

    socket->write( Data );
    socket->flush();
    socket->disconnectFromHost();
    socket->waitForDisconnected();
}

void WorkThread::disconnected()
{
    qDebug() << socketDescriptor << " Disconnected";

    socket->deleteLater();
    exit(0);
}
