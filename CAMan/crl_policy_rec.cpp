#include "crl_policy_rec.h"


CRLPolicyRec::CRLPolicyRec()
{

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

void CRLPolicyRec::setThisUpdate( time_t tThisUpdate )
{
    m_tThisUpdate = tThisUpdate;
}

void CRLPolicyRec::setNextUpdate( time_t tNextUpdate )
{
    m_tNextUpdate = tNextUpdate;
}
