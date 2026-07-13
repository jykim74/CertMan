#ifndef ACME_STAT_H
#define ACME_STAT_H

#include <QObject>
#include <QString>

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
    const QString getIdentifier() { return identifier_; };
    const QString getContact() { return contact_; };

    void setStatus( int nStatus );
    void setPubKey( const QString strPubKey );
    void setCSR( const QString strCSR );
    void setCert( const QString strCert );
    void setNonce( const QString strNonce );
    void setIdentifier( const QString strIdentifier );
    void setContact( const QString strContact );

private:
    int         status_;
    QString     pub_key_;
    QString     csr_;
    QString     cert_;
    QString     nonce_;
    QString     identifier_;
    QString     contact_;
};

#endif // ACME_STAT_H
