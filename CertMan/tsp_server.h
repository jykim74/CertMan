#ifndef TSP_SERVER_H
#define TSP_SERVER_H

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>

#include "js_bin.h"
#include "js_pkcs11.h"


class TSPServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit TSPServer( QObject *parent = nullptr );
    ~TSPServer();

    void startServer( int nPort );
    void setLogEdit( QPlainTextEdit *pEdit );
    void setTSPCert( const BIN *pCert );
    void setTSPPriKey( const BIN *pPriKey, bool bP11 = false );
    void setTLS( const BIN *pCert, const BIN *pPriKey );

public slots:
    int readReady();
    int readTLSReady();

private :
    int procTSP( const BIN *pReq, BIN *pRsp );


private:
    QPlainTextEdit* log_edit_;

    BIN tsp_cert_;
    BIN tsp_pri_key_;
    BIN tls_cert_;
    BIN tls_pri_key_;
    QTcpSocket *client_;
    QSslSocket *tls_client_;
    bool p11_;
    bool tls_;

protected:
    void incomingConnection( qintptr socketDescriptor );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // TSP_SERVER_H
