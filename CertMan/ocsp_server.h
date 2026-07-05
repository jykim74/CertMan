#ifndef OCSP_SERVER_H
#define OCSP_SERVER_H

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>
#include <QSslSocket>

#include "js_bin.h"
#include "js_pkcs11.h"
#include "js_ocsp.h"

class OCSPServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit OCSPServer( QObject *parent = nullptr );
    ~OCSPServer();

    void setNeedSign( bool bVal );
    int startServer( int nPort );
    void setLogEdit( QPlainTextEdit *pEdit );
    void setCACert( const BIN *pCert );
    void setOCSPCert( const BIN *pCert );
    void setOCSPPriKey( const BIN *pPriKey, bool bP11 = false );
    void setTLS( const BIN *pCert, const BIN *pPriKey );

public slots:
    int readReady();
    void onEncrypted();

    void onTLSReadyRead();
    void onTLSDisconnected();

private :
    enum State
    {
        WaitingHeader,
        WaitingBody
    };

    int procOCSP( const BIN *pReq, BIN *pRsp );
    int getCertStatus( JCertIDInfo *pIDInfo, JCertStatusInfo *pStatusInfo );

    void processBuffer();
    void parseHeader(const QByteArray &header);
    void resetState();
    void processOCSP();


private:
    QPlainTextEdit* log_edit_;

    BIN ca_cert_;
    BIN ocsp_cert_;
    BIN ocsp_pri_key_;
    BIN tls_cert_;
    BIN tls_pri_key_;

    QTcpSocket *client_;
    QSslSocket *tls_client_;

    bool need_sign_;
    bool p11_;
    bool tls_;

    QByteArray buffer_;
    State state_ = WaitingHeader;
    int content_len_ = 0;
    QString method_;
    QString path_;
    QString version_;

    QMap<QString, QString> headers_;
    QByteArray body_;

protected:
    void incomingConnection( qintptr socketDescriptor );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // OCSP_SERVER_H
