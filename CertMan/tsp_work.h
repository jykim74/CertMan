#ifndef TSP_WORK_H
#define TSP_WORK_H

#include <QThread>
#include <QtNetwork/QTcpSocket>
#include <QPlainTextEdit>

#include "js_bin.h"

class TspWork : public QThread
{
    Q_OBJECT

public:
    explicit TspWork( qintptr ID, QObject *parent = 0 );
    ~TspWork();
    void setTSPCert( const BIN *pCert );
    void setTSPPriKey( const BIN *pPriKey );

    void run();

signals:
    void error( QTcpSocket::SocketError socketError );

public slots:
    void readyRead();
    void disconnected();

private:
    QTcpSocket *socket;
    qintptr     socketDescriptor;
    BIN         tsp_cert_;
    BIN         tsp_pri_key_;

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // TSP_WORK_H
