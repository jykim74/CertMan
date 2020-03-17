#include "cert_rec.h"

CertRec::CertRec()
{
    m_nNum = -1;
    m_nKeyNum = -1;
    m_nUserNum = -1;
    m_strCert = "";
    m_strSignAlg = "";
    m_bSelf = false;
    m_bCA = false;
    m_nIssuerNum = -1;
    m_strSubjectDN = "";
    m_nStatus = -1;
    m_strCRLDP = "";
}


void CertRec::setNum( int nNum )
{
    m_nNum = nNum;
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
    m_bSelf = bSelf;
}

void CertRec::setCA( bool bCA )
{
    m_bCA = bCA;
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
