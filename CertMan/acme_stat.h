#ifndef ACME_STAT_H
#define ACME_STAT_H

#include <QObject>
#include <QString>
#include <QMap>
#include <QJsonArray>
#include <QJsonObject>

#define JS_ACME_STATUS_START        0x00000001
#define JS_ACME_STATUS_NEWORDER     0x00000002
#define JS_ACME_STATUS_AUTH         0x00000004
#define JS_ACME_STATUS_CHALLENGE    0x00000008
#define JS_ACME_STATUS_CHAL_DONE    0x00000010
#define JS_ACME_STATUS_CERTIFICATE  0x00000020

#define JS_CHALL_FLAG_HTTP_01       0x00000001
#define JS_CHALL_FLAG_DNS_01        0x00000002
#define JS_CHALL_FLAG_TLS_ALPN_01   0x00000004


enum ACMEStatus{
    ACME_STATUS_PENDING = 0,
    ACME_STATUS_PROCESSING,
    ACME_STATUS_READY,
    ACME_STATUS_VALID,
    ACME_STATUS_INVALID,
    ACME_STATUS_DEACTIVATED,
    ACME_STATUS_EXPIRED,
    ACME_STATUS_REVOKED
};

class ACMEAuth
{
public:
    ACMEAuth()
    {
        status_ = -1;
        type_ = "";
    }

    int         status_;
    QString     type_;
    QString     id_;
};

class ACMEOrder
{
public :
    ACMEOrder()
    {
        status_ = -1;
    }

    int         status_;
    QString     kid_;
};

class ACMEChall
{
public :
    ACMEChall()
    {
        status_ = -1;
    }

    int         status_;
    QString     auth_id_;
    QString     type_;
};

const QString getACMEStatusName( ACMEStatus status );

class ACMEStat : public QObject
{
    Q_OBJECT
public:
    ACMEStat();

    // 복사 생성자
    ACMEStat(const ACMEStat& other);

    // 대입 연산자
    ACMEStat& operator=(const ACMEStat& other);

    int getStatus() { return status_; };
    const QString getPubKey() { return pub_key_; };
    const QString getCSR() { return csr_; };
    const QString getCert() { return cert_; };
    const QString getNonce() { return nonce_; };

    const QJsonArray getIDListArray();
    const QJsonArray getContactArray();


    const ACMEAuth getAuth( const QString strToken );
    const ACMEOrder getOrder( const QString strToken );
    const ACMEChall getChall( const QString strToken );
    const QMap<QString, ACMEAuth> getAuths() { return auths_; };
    const QMap<QString, ACMEOrder> getOrders() { return orders_; };
    const QMap<QString, ACMEChall> getChalls() { return challs_; };

    void setStatus( int nStatus );
    void setPubKey( const QString strPubKey );
    void setCSR( const QString strCSR );
    void setCert( const QString strCert );
    void setNonce( const QString strNonce );
    void addContact( const QString strContact );
    void setValidTime( time_t time );

    void addAuth( const QString strToken, const ACMEAuth auth );
    void addChall( const QString strToken, const ACMEChall chall );
    void setAuthStatus( const QString strID, int nStatus );
    void setChallStatus( const QString strID, int nStatus );
    void setOrderStatus( const QString strID, int nStatus );
    void setAuthLinkStatus( const QString strLink, int nStatus );
    bool isAuthDone();


    void addOrder( const QString strToken, const ACMEOrder order );
    const QStringList getIDList();
    const QStringList getOrderList();
    const QStringList getAuthList();
    const QString getValidTime();
    time_t getValidTimeT() { return valid_time_; };

private:
    int             status_;
    QString         pub_key_;
    QString         csr_;
    QString         cert_;
    QString         nonce_;
    QStringList     contact_list_;
    time_t          valid_time_;

    QMap<QString, ACMEAuth> auths_;
    QMap<QString, ACMEChall> challs_;
    QMap<QString, ACMEOrder> orders_;
};

#endif // ACME_STAT_H
