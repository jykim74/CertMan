#ifndef WORK_THREAD_H
#define WORK_THREAD_H

#include <QThread>
#include <QtNetwork/QTcpSocket>
#include <QPlainTextEdit>

class WorkThread : public QThread
{
    Q_OBJECT

public:
    explicit WorkThread( qintptr ID, QObject *parent = 0 );

    void setLogEdit( QPlainTextEdit *pEdit );

    void run();

signals:
    void error( QTcpSocket::SocketError socketError );

public slots:
    void readyRead();
    void disconnected();

private:
    QTcpSocket *socket;
    qintptr     socketDescriptor;

    QPlainTextEdit* log_edit_;

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // WORK_THREAD_H
