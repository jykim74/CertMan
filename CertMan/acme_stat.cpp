#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "acme_stat.h"

ACMEStat::ACMEStat()
{
    status_ = -1;
    pub_key_.clear();
    csr_.clear();
    cert_.clear();
    nonce_.clear();
    id_list_.clear();
    contact_.clear();
    auths_.clear();
    orders_.clear();
}

// 복사 생성자
ACMEStat::ACMEStat(const ACMEStat& other)
{
    status_ = other.status_;
    pub_key_ = other.pub_key_;
    csr_ = other.csr_;
    cert_ = other.cert_;
    nonce_ = other.nonce_;
    id_list_ = other.id_list_;
    contact_ = other.contact_;
    auths_ = other.auths_;
    orders_ = other.orders_;
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
        id_list_ = other.id_list_;
        contact_ = other.contact_;
        auths_ = other.auths_;
        orders_ = other.orders_;
    }

    return *this;
}

const QString ACMEStat::getIDListJson()
{
    QJsonArray jArr;
    QJsonDocument jDoc;

    for( int i = 0; i < id_list_.size(); i++ )
    {
        QJsonObject jObj;

        jObj["type"] = "dns";
        jObj["value"] = id_list_.at(i);

        jArr.append( jObj );
    }

    jDoc.setArray( jArr );

    return jDoc.toJson();
}

const ACMEAuth ACMEStat::getAuth( const QString strToken )
{
    return auths_[strToken];
}

const ACMEOrder ACMEStat::getOrder( const QString strToken )
{
    return orders_[strToken];
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

void ACMEStat::setID( const QString strID )
{
    id_list_.append( strID );
}

void ACMEStat::setContact( const QString strContact )
{
    contact_ = strContact;
}

void ACMEStat::setOrder( const QString strOrder )
{
    order_list_.append( strOrder );
}

void ACMEStat::addAuth( const QString strToken, const ACMEAuth auth )
{
    auths_.insert( strToken, auth );
}

void ACMEStat::addOrder( const QString strToken, const ACMEOrder order )
{
    orders_.insert( strToken, order );
}
