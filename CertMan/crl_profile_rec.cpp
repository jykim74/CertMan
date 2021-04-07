#include "crl_profile_rec.h"


CRLProfileRec::CRLProfileRec()
{
    m_nNum = -1;
    m_nVersion = -1;
    m_strName = "";
    m_strHash = "";
    m_tLastUpdate = -1;
    m_tNextUpdate = -1;
}

void CRLProfileRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CRLProfileRec::setVersion( int nVersion )
{
    m_nVersion = nVersion;
}

void CRLProfileRec::setName( QString strName )
{
    m_strName = strName;
}

void CRLProfileRec::setHash( QString strHash )
{
    m_strHash = strHash;
}

void CRLProfileRec::setLastUpdate( time_t tLastUpdate )
{
    m_tLastUpdate = tLastUpdate;
}

void CRLProfileRec::setNextUpdate( time_t tNextUpdate )
{
    m_tNextUpdate = tNextUpdate;
}

