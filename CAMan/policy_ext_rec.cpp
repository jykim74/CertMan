#include "policy_ext_rec.h"

PolicyExtRec::PolicyExtRec()
{
    m_nSeq = -1;
    m_nPolicyNum = -1;
    m_bCritical = false;
    m_strSN = "";
    m_strValue = "";
}

void PolicyExtRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void PolicyExtRec::setPolicyNum( int nPolicyNum )
{
    m_nPolicyNum = nPolicyNum;
}

void PolicyExtRec::setCritical( bool bCritical )
{
    m_bCritical = bCritical;
}

void PolicyExtRec::setSN( QString strSN )
{
    m_strSN = strSN;
}

void PolicyExtRec::setValue( QString strValue )
{
    m_strValue = strValue;
}
