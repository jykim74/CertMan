#include "policy_ext_rec.h"

PolicyExtRec::PolicyExtRec()
{

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
