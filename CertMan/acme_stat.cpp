#include "acme_stat.h"

ACMEStat::ACMEStat()
{
    status_ = -1;
    pub_key_.clear();
    csr_.clear();
    cert_.clear();
    nonce_.clear();
    identifier_.clear();
    contact_.clear();
}

// 복사 생성자
ACMEStat::ACMEStat(const ACMEStat& other)
{
    status_ = other.status_;
    pub_key_ = other.pub_key_;
    csr_ = other.csr_;
    cert_ = other.cert_;
    nonce_ = other.nonce_;
    identifier_ = other.identifier_;
    contact_ = other.contact_;
}

// 대입 연산자
ACMEStat& ACMEStat::operator=(const ACMEStat& other)
{
    // 자기 자신 대입 방지
    if (this != &other)
    {
        status_ = other.status_;
        pub_key_ = other.pub_key_;
        csr_ = other.csr_;
        cert_ = other.cert_;
        nonce_ = other.nonce_;
        identifier_ = other.identifier_;
        contact_ = other.contact_;
    }

    return *this;
}

void ACMEStat::setStatus( int nStatus )
{
    status_ = nStatus;
}

void ACMEStat::setPubKey( const QString strPubKey )
{
    pub_key_ = strPubKey;
}

void ACMEStat::setCSR( const QString strCSR )
{
    csr_ = strCSR;
}

void ACMEStat::setCert( const QString strCert )
{
    cert_ = strCert;
}

void ACMEStat::setNonce( const QString strNonce )
{
    nonce_ = strNonce;
}

void ACMEStat::setIdentifier( const QString strIdentifier )
{
    identifier_ = strIdentifier;
}

void ACMEStat::setContact( const QString strContact )
{
    contact_ = strContact;
}
