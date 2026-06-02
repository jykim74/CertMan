#ifndef WORK_THREAD_H
#define WORK_THREAD_H

#include <QThread>
#include <QtNetwork/QTcpSocket>

class WorkThread : public QThread
{
    Q_OBJECT

public:
    explicit WorkThread( qintptr ID, QObject *parent = 0 );

    void run();

signals:
    void error( QTcpSocket::SocketError socketError );

public slots:
    void readyRead();
    void disconnected();

private:
    QTcpSocket *socket;
    qintptr     socketDescriptor;
};

#endif // WORK_THREAD_H
