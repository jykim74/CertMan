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

/*
200 OK	요청 성공	GET, POST-as-GET 성공
201 Created	리소스 생성	NewAccount, NewOrder 성공
204 No Content	내용 없음	인증서 폐기 등 응답 본문이 없는 경우
400 Bad Request	잘못된 요청	malformed, badNonce, badCSR
401 Unauthorized	인증 실패	JWS 서명 오류, 계정 인증 실패
403 Forbidden	권한 없음	unauthorized, CAA 정책 위반 등
404 Not Found	리소스 없음	존재하지 않는 Order, Authorization
405 Method Not Allowed	메서드 오류	GET 대신 POST가 필요한 경우
409 Conflict	충돌	계정 중복 등 일부 서버 구현
429 Too Many Requests	요청 제한 초과	rateLimited
500 Internal Server Error	서버 내부 오류	serverInternal
503 Service Unavailable	서비스 사용 불가	서버 점검, 일시적 장애
*/

enum AcmeError
{
    AccountDoesNotExist,    // 지정한 계정이 존재하지 않음
    AlreadyRevoked,         // 인증서가 이미 폐기됨
    BadCSR,                 // CSR이 올바르지 않음
    BadNonce,               // Nonce가 잘못되었거나 만료됨
    BadPublicKey,           // 공개키가 유효하지 않음
    BadRevocationReason,    // 폐기 사유 코드가 잘못됨
    BadSignatureAlgorithm,  // 지원하지 않는 서명 알고리즘
    CAA,                    // CAA 레코드 정책 때문에 발급 불가
    Compound,               // 여러 개의 오류를 포함하는 복합 오류
    Connection,             // CA가 대상 서버에 연결할 수 없음
    DNS,                    // DNS 조회 실패
    ExternalAccountRequired,// External Account Binding(EAB)이 필요함
    IncorrectResponse,      // Challenge 응답이 올바르지 않음
    InvalidContact,         // Contact 정보가 잘못됨
    Malformed,              // 요청 형식이 잘못됨
    OrderNotReady,          // Order가 아직 준비되지 않음
    RateLimited,            // 요청 제한 초과
    RejectedIdentifier,     // 도메인 식별자가 거부됨
    ServerInternal,         // 서버 내부 오류
    TLS,                    // TLS 검증 실패
    Unauthorized,           // 권한 없음 또는 Challenge 실패
    UnsupportedContact,     // 지원하지 않는 Contact 형식
    UnsupportedIdentifier,  // 지원하지 않는 Identifier 형식
    UserActionRequired,     // 사용자 추가 조치 필요
    UnknownError
};

const QString ACMEErrString( AcmeError error );

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

    int procACME( const QString strMethod, const QString strPath, const BIN *pReq, QStringList& rspHeaders, BIN *pRsp );
    int procEST( const char *pPath, const BIN *pReq, BIN *pRsp );

    void processBuffer();
    void parseHeader(const QByteArray &header);
    void resetState();
    void processACME();


    int runACME_Directory( QJsonObject& rspJson );
    int runACME_NewAccount( ACMEObject& acmeObj, QJsonObject& rspJson );
    int runACME_NewOrder( ACMEObject& acmeObj, QJsonObject& rspJson );
    int runACME_Authorization( ACMEObject& acmeObj, QJsonObject& rspJson );
    int runACME_Finalize( ACMEObject& acmeObj, QJsonObject& rspJson );
    int runACME_Challenge( ACMEObject& acmeObj, QJsonObject& rspJson );
    int runACME_Account( ACMEObject& acmeObj, const QString strKID, QJsonObject& rspJson );
    int runACME_Location( ACMEObject& acmeObj, const QString strKID, QJsonObject& rspJson );
    int runACME_Certificate( ACMEObject& acmeObj, BINList **ppCertList );
    int runACME_Order( ACMEObject& acmeObj, const QString strKID, QJsonObject& rspJson );
    int runACME_Orders( ACMEObject& acmeObj, const QString strKID, QJsonObject& rspJson );
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

    void makeErrorRsp( int nStatus, QJsonObject& rspObj );

    int issueCert( const BIN *pCSR, BIN *pCert );
    int makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert );
    const QString strACME_URL( const QString strCmd, const QString strID = "" );
    int getChainList( BINList **ppChainList );

    void makeACMEFail( const QString strType, const QString strDetail, int nStatus, QJsonObject& rspJson );
};

#endif // ACME_SERVER_H
