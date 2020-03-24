#include "cert_policy_rec.h"

CertPolicyRec::CertPolicyRec()
{
    m_nNum = -1;
    m_nVersion = -1;
    m_uNotBefore = -1;
    m_uNotAfter = -1;
    m_strName = "";
    m_strHash = "";
    m_strDNTemplate = "";
}

void CertPolicyRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CertPolicyRec::setName( QString strName )
{
    m_strName = strName;
}

void CertPolicyRec::setVersion( int nVersion )
{
    m_nVersion = nVersion;
}

void CertPolicyRec::setHash( QString strHash )
{
    m_strHash = strHash;
}

void CertPolicyRec::setDNTemplate( QString strDNTemplate )
{
    m_strDNTemplate = strDNTemplate;
}

void CertPolicyRec::setNotBefore( long uNotBefore )
{
    m_uNotBefore = uNotBefore;
}

void CertPolicyRec::setNotAfter( long uNotAfter )
{
    m_uNotAfter = uNotAfter;
}
