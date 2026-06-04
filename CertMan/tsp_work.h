#ifndef TSP_WORK_H
#define TSP_WORK_H

#include <QThread>
#include <QtNetwork/QTcpSocket>
#include <QPlainTextEdit>

class TspWork : public QThread
{
    Q_OBJECT

public:
    explicit TspWork( qintptr ID, QObject *parent = 0 );
    void run();

signals:
    void error( QTcpSocket::SocketError socketError );

public slots:
    void readyRead();
    void disconnected();

private:
    QTcpSocket *socket;
    qintptr     socketDescriptor;

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // TSP_WORK_H
