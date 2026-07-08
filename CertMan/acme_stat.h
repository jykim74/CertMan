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
    ACMEStat(const ACMEStat& other)
    {
        status_ = other.status_;
        key_ = other.key_;
        csr_ = other.csr_;
        cert_ = other.cert_;
        nonce_ = other.nonce_;
        identifier_ = other.identifier_;
        contact_ = other.contact_;
    }

    // 대입 연산자
    ACMEStat& operator=(const ACMEStat& other)
    {
        // 자기 자신 대입 방지
        if (this != &other)
        {
            status_ = other.status_;
            key_ = other.key_;
            csr_ = other.csr_;
            cert_ = other.cert_;
            nonce_ = other.nonce_;
            identifier_ = other.identifier_;
            contact_ = other.contact_;
        }

        return *this;
    }

    int getStatus() { return status_; };
    const QString getKey() { return key_; };
    const QString getCSR() { return csr_; };
    const QString getCert() { return cert_; };
    const QString getNonce() { return nonce_; };
    const QString getIdentifier() { return identifier_; };
    const QString getContact() { return contact_; };

    void setStatus( int nStatus );
    void setKey( const QString strKey );
    void setCSR( const QString strCSR );
    void setCert( const QString strCert );
    void setNonce( const QString strNonce );
    void setIdentifier( const QString strIdentifier );
    void setContact( const QString strContact );

private:
    int         status_;
    QString     key_;
    QString     csr_;
    QString     cert_;
    QString     nonce_;
    QString     identifier_;
    QString     contact_;
};

#endif // ACME_STAT_H
