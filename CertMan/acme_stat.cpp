#include "acme_stat.h"

ACMEStat::ACMEStat()
{
    status_ = -1;
    key_.clear();
    csr_.clear();
    cert_.clear();
    nonce_.clear();
    identifier_.clear();
    contact_.clear();
}

void ACMEStat::setStatus( int nStatus )
{
    status_ = nStatus;
}

void ACMEStat::setKey( const QString strKey )
{
    key_ = strKey;
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
