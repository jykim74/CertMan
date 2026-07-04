#ifndef ACME_SERVER_H
#define ACME_SERVER_H

#include <QObject>
#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>
#include <QSslSocket>

#include "js_bin.h"
#include "js_pkcs11.h"
#include "js_cmp.h"
#include "js_scep.h"
#include "js_pki_x509.h"
#include "js_cmp.h"

#include "db_mgr.h"

const QString kEST_CACerts = "cacerts";
const QString kEST_SimpleEnroll = "simpleenroll";
const QString kEST_SimpleReenroll = "simplereenroll";
const QString kEST_FullCMC = "fullcmc";
const QString kEST_ServerKeyGen = "serverkeygen";
const QString kEST_CSRAttrs = "csrattrs";

class ACMEServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit ACMEServer( QObject *parent = nullptr  );
    ~ACMEServer();

    void startServer( int nPort );
    void setLogEdit( QPlainTextEdit *pEdit );
    void setCACert( const BIN *pCert );
    void setCANum( int nNum );
    void setProfileNum( int nNum );
    void setCAPriKey( const BIN *pPriKey, bool bP11 = false );
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

    int procACME( const BIN *pReq, BIN *pRsp );
    int procEST( const char *pPath, const BIN *pReq, BIN *pRsp );

    void processBuffer();
    void parseHeader(const QByteArray &header);
    void resetState();
    void processACME();

private:
    QPlainTextEdit* log_edit_;

    int ca_num_;
    int profile_num_;
    BIN ca_cert_;
    BIN ca_pri_key_;
    BIN tls_cert_;
    BIN tls_pri_key_;
    QTcpSocket *client_;
    QSslSocket *tls_client_;
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
    JNameValList *param_list_;

private:
    void incomingConnection( qintptr socketDescriptor );
    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );

    int issueCert( const BIN *pCSR, BIN *pCert );
    int makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert );
};

#endif // ACME_SERVER_H
