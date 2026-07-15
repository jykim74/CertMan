#ifndef ACME_SERVER_H
#define ACME_SERVER_H

#include <QObject>
#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>
#include <QSslSocket>

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "js_bin.h"
#include "js_pkcs11.h"
#include "js_cmp.h"
#include "js_scep.h"
#include "js_pki_x509.h"
#include "js_cmp.h"

#include "db_mgr.h"
#include "acme_stat.h"
#include "acme_object.h"

static QString kACME_Directory = "DIRECTORY";
static QString kACME_Location = "LOCATION";
static QString kACME_Account = "ACCOUNT";
static QString kACME_Order = "ORDER";
static QString kACME_Orders = "ORDERS";

static QString kACME_KeyChange = "KEYCHANGE";
static QString kACME_NewAccount = "NEWACCOUNT";
static QString kACME_NewNonce = "NEWNONCE";
static QString kACME_NewOrder = "NEWORDER";
static QString kACME_RenewalInfo = "RENEWALINFO";
static QString kACME_RevokeCert = "REVOKECERT";

static QString kACME_NewAuthz = "NEWAUTHZ";
static QString kACME_Finalize = "FINALIZE";
static QString kACME_Certificate = "CERTIFICATE";

static QString kACME_Authorization = "AUTHORIZATION";
static QString kACME_Challenge = "CHALLENGE";

static QString kACME_Deactivate = "DEACTIVATE";
static QString kACME_UpdateAccount = "UPDATEACCOUNT";

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

    int startServer( int nPort );
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

    int procACME( const char *pPath, const BIN *pReq, QStringList& rspHeaders, BIN *pRsp );
    int procEST( const char *pPath, const BIN *pReq, BIN *pRsp );

    void processBuffer();
    void parseHeader(const QByteArray &header);
    void resetState();
    void processACME();


    int runACME_Directory( QJsonObject& rspJson );
    int runACME_NewAccount( ACMEObject& acmeObj, QJsonObject& rspJson );
    int runACME_NewOrder( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Authorization( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Finalize( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Challenge( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Account( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Location( QJsonObject& rspJson );
    int runACME_Certificate( BINList **ppCertList );
    int runACME_Order( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Orders( const QJsonObject request, QJsonObject& rspJson );
    int runACME_KeyChange( const QJsonObject request, QJsonObject& rspJson );
    int runACME_RenewalInfo( const QJsonObject request, QJsonObject& rspJson );
    int runACME_RevokeCert( const QJsonObject request, QJsonObject& rspJson );
    int runACME_NewAuthz( const QJsonObject request, QJsonObject& rspJson );
    int runACME_Deactivate( const QJsonObject request, QJsonObject& rspJson );
    int runACME_UpdateAccount( const QJsonObject request, QJsonObject& rspJson );

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
    int port_;

    QMap<QString, ACMEStat> acme_stats_;

    QByteArray buffer_;
    State state_ = WaitingHeader;
    int content_len_ = 0;
    QString method_;
    QString path_;
    QString version_;
    QString nonce_;

    QMap<QString, QString> headers_;
    QByteArray body_;
    JNameValList *param_list_;

private:
    void incomingConnection( qintptr socketDescriptor );
    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );

    int issueCert( const BIN *pCSR, BIN *pCert );
    int makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert );
    const QString strACME_URL( const QString strCmd, const QString strID = "" );

    void makeACMEFail( const QString strType, const QString strDetail, int nStatus, QJsonObject& rspJson );
};

#endif // ACME_SERVER_H
