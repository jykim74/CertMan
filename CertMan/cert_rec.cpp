/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "cert_rec.h"
#include "commons.h"
#include "js_define.h"

CertRec::CertRec()
{
    m_nNum = -1;
    m_tRegTime = 0;
    m_tNotBefore = 0;
    m_tNotAfter = 0;
    m_nKeyNum = -1;
    m_nUserNum = -1;
    m_strCert = "";
    m_strSignAlg = "";
    m_nSelf = 0;
    m_nCA = 0;
    m_nIssuerNum = -1;
    m_strSubjectDN = "";
    m_nStatus = -1;
    m_strCRLDP = "";
}


void CertRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CertRec::setRegTime(time_t tRegTime)
{
    m_tRegTime = tRegTime;
}

void CertRec::setNotBefore( time_t tNotBefore )
{
    m_tNotBefore = tNotBefore;
}

void CertRec::setNotAfter( time_t tNotAfter )
{
    m_tNotAfter = tNotAfter;
}

void CertRec::setKeyNum( int nKeyNum )
{
    m_nKeyNum = nKeyNum;
}

void CertRec::setUserNum(int nUserNum)
{
    m_nUserNum = nUserNum;
}

void CertRec::setSignAlg( QString strSignAlg )
{
    m_strSignAlg = strSignAlg;
}

void CertRec::setCert( QString strCert )
{
    m_strCert = strCert;
}

void CertRec::setSelf( bool bSelf )
{
    m_nSelf = bSelf;
}

void CertRec::setCA( bool bCA )
{
    m_nCA = bCA;
}

void CertRec::setIssuerNum( int nIssuerNum )
{
    m_nIssuerNum = nIssuerNum;
}

void CertRec::setSubjectDN( QString strSubjectDN )
{
    m_strSubjectDN = strSubjectDN;
}

void CertRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}

void CertRec::setSerial( QString strSerial )
{
    m_strSerial = strSerial;
}

void CertRec::setDNHash( QString strDNHash )
{
    m_strDNHash = strDNHash;
}

void CertRec::setKeyHash( QString strKeyHash )
{
    m_strKeyHash = strKeyHash;
}

void CertRec::setCRLDP(QString strCRLDP)
{
    m_strCRLDP = strCRLDP;
}

const QIcon CertRec::getIcon( time_t now_t )
{
    if( m_nIssuerNum == kImportNum )
    {
        if( m_tNotAfter < now_t )
            return QIcon( ":/images/im_cert_expired.png" );
        else
            return QIcon( ":/images/im_cert.png" );
    }

    if( m_nSelf == true )
    {
        if( m_tNotAfter < now_t )
            return QIcon( ":/images/rca_expired.png" );
        else
            return QIcon( ":/images/rca.png" );
    }

    if( m_nCA == true )
    {
        if( m_tNotAfter < now_t )
            return QIcon( ":/images/ca_expired.png" );
        else
        {
            if( m_nStatus == JS_CERT_STATUS_REVOKE )
                return QIcon( ":/images/ca_revoked.png" );
            else
                return QIcon( ":/images/ca.png" );
        }
    }

    if( m_tNotAfter < now_t )
        return QIcon( ":/images/cert_expired.png" );
    else
    {
        if( m_nStatus == JS_CERT_STATUS_REVOKE )
            return QIcon( ":/images/cert_revoked.png" );
    }

    return QIcon( ":/images/cert.png" );
}
