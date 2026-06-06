#ifndef OCSP_SERVER_H
#define OCSP_SERVER_H

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>

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
    void startServer( int nPort );
    void setLogEdit( QPlainTextEdit *pEdit );
    void setOCSPCert( const BIN *pCert );
    void setOCSPPriKey( const BIN *pPriKey );

public slots:
    int readReady();

private :
    int procOCSP( const BIN *pReq, BIN *pRsp );
    int getCertStatus( JCertIDInfo *pIDInfo, JCertStatusInfo *pStatusInfo );


private:
    QPlainTextEdit* log_edit_;

    BIN ocsp_cert_;
    BIN ocsp_pri_key_;
    QTcpSocket *client_;
    bool need_sign_;

protected:
    void incomingConnection( qintptr socketDescriptor );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // OCSP_SERVER_H
