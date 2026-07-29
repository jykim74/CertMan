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
    contact_.clear();
    auths_.clear();
    challs_.clear();
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
    contact_ = other.contact_;
    auths_ = other.auths_;
    challs_ = other.challs_;
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
        contact_ = other.contact_;
        auths_ = other.auths_;
        challs_ = other.challs_;
        orders_ = other.orders_;
    }

    return *this;
}

const QJsonArray ACMEStat::getIDListArray()
{
    QJsonArray jArr;
    QMap<QString, ACMEAuth>::iterator i;

    for( i = auths_.begin(); i != auths_.end(); ++i )
    {
        QString key = i.key();
        ACMEAuth auth = i.value();

        QJsonObject jObj;
        jObj["type"] = auth.type_;
        jObj["value"] = auth.id_;

        jArr.append( jObj );
    }

    return jArr;
}

const ACMEAuth ACMEStat::getAuth( const QString strToken )
{
    return auths_[strToken];
}

const ACMEOrder ACMEStat::getOrder( const QString strToken )
{
    return orders_[strToken];
}

const ACMEChall ACMEStat::getChall( const QString strToken )
{
    return challs_[strToken];
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

void ACMEStat::setContact( const QString strContact )
{
    contact_ = strContact;
}

void ACMEStat::addAuth( const QString strToken, const ACMEAuth auth )
{
    auths_.insert( strToken, auth );
}

void ACMEStat::addChall( const QString strToken, const ACMEChall chall )
{
    challs_.insert( strToken, chall );
}

void ACMEStat::setAuthStatus( const QString strID, int nStatus )
{
    QMap<QString, ACMEAuth>::iterator i;

    for( i = auths_.begin(); i != auths_.end(); ++i )
    {
        QString key = i.key();
        ACMEAuth auth = i.value();

        if( auth.id_ == strID )
        {
            auth.status_ = nStatus;
        }
    }
}

void ACMEStat::setChallStatus( const QString strID, int nStatus )
{
    QMap<QString, ACMEChall>::iterator i;

    for( i = challs_.begin(); i != challs_.end(); ++i )
    {
        QString key = i.key();
        ACMEChall chall = i.value();

        if( key == strID )
        {
            chall.status_ = nStatus;
        }
    }
}

void ACMEStat::setOrderStatus( const QString strID, int nStatus )
{
    QMap<QString, ACMEOrder>::iterator i;

    for( i = orders_.begin(); i != orders_.end(); ++i )
    {
        QString key = i.key();
        ACMEOrder order = i.value();

        if( key == strID )
        {
            order.status_ = nStatus;
        }
    }
}

void ACMEStat::setAuthLinkStatus( const QString strLink, int nStatus )
{
    QMap<QString, ACMEAuth>::iterator i;

    ACMEAuth auth = auths_[strLink];
    auth.status_ = nStatus;
    auths_.insert( strLink, auth );
}

bool ACMEStat::isAuthDone()
{
    QMap<QString, ACMEAuth>::iterator i;

    for( i = auths_.begin(); i != auths_.end(); ++i )
    {
        QString key = i.key();
        ACMEAuth auth = i.value();

        if( auth.status_ != ACME_Done )
            return false;
    }

    return true;
}

void ACMEStat::addOrder( const QString strToken, const ACMEOrder order )
{
    orders_.insert( strToken, order );
}

const QStringList ACMEStat::getIDList()
{
    QStringList idList;

    QMap<QString, ACMEAuth>::iterator i;

    for( i = auths_.begin(); i != auths_.end(); ++i )
    {
        QString key = i.key();
        ACMEAuth auth = i.value();
        idList.append( auth.id_ );
    }

    return idList;
}

const QStringList ACMEStat::getOrderList()
{
    QStringList idList;

    QMap<QString, ACMEOrder>::iterator i;

    for( i = orders_.begin(); i != orders_.end(); ++i )
    {
        QString key = i.key();
        idList.append( key );
    }

    return idList;
}
