#include "crl_policy_rec.h"


CRLPolicyRec::CRLPolicyRec()
{
    m_nNum = -1;
    m_nVersion = -1;
    m_strName = "";
    m_strHash = "";
    m_tLastUpdate = -1;
    m_tNextUpdate = -1;
}

void CRLPolicyRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CRLPolicyRec::setVersion( int nVersion )
{
    m_nVersion = nVersion;
}

void CRLPolicyRec::setName( QString strName )
{
    m_strName = strName;
}

void CRLPolicyRec::setHash( QString strHash )
{
    m_strHash = strHash;
}

void CRLPolicyRec::setLastUpdate( time_t tLastUpdate )
{
    m_tLastUpdate = tLastUpdate;
}

void CRLPolicyRec::setNextUpdate( time_t tNextUpdate )
{
    m_tNextUpdate = tNextUpdate;
}
