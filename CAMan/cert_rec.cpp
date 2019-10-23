#include "cert_rec.h"

CertRec::CertRec()
{

}


void CertRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CertRec::setKeyNum( int nKeyNum )
{
    m_nKeyNum = nKeyNum;
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

