#ifndef ACME_STAT_H
#define ACME_STAT_H

#include <QObject>
#include <QString>
#include <QMap>

#define JS_ACME_STATUS_START        0x00000001
#define JS_ACME_STATUS_NEWORDER     0x00000002
#define JS_ACME_STATUS_AUTH         0x00000004
#define JS_ACME_STATUS_CHALLENGE    0x00000008
#define JS_ACME_STATUS_CHAL_DONE    0x00000010
#define JS_ACME_STATUS_CERTIFICATE  0x00000020

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
};

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
    const QStringList getIDList() { return id_list_; };
    const QString getIDListJson();

    const QString getContact() { return contact_; };
    const QStringList getOrderList() { return order_list_; };

    const ACMEAuth getAuth( const QString strToken );
    const ACMEOrder getOrder( const QString strToken );

    void setStatus( int nStatus );
    void setPubKey( const QString strPubKey );
    void setCSR( const QString strCSR );
    void setCert( const QString strCert );
    void setNonce( const QString strNonce );
    void setID( const QString strID );
    void setContact( const QString strContact );
    void setOrder( const QString strOrder );

    void addAuth( const QString strToken, const ACMEAuth auth );
    void addOrder( const QString strToken, const ACMEOrder order );

private:
    int             status_;
    QString         pub_key_;
    QString         csr_;
    QString         cert_;
    QString         nonce_;
    QStringList     id_list_;
    QString         contact_;
    QStringList     order_list_;

    QMap<QString, ACMEAuth> auths_;
    QMap<QString, ACMEOrder> orders_;
};

#endif // ACME_STAT_H
