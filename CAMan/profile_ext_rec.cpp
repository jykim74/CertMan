#include "profile_ext_rec.h"

ProfileExtRec::ProfileExtRec()
{
    m_nSeq = -1;
    m_nProfileNum = -1;
    m_bCritical = false;
    m_strSN = "";
    m_strValue = "";
}

void ProfileExtRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void ProfileExtRec::setProfileNum( int nProfileNum )
{
    m_nProfileNum = nProfileNum;
}

void ProfileExtRec::setCritical( bool bCritical )
{
    m_bCritical = bCritical;
}

void ProfileExtRec::setSN( QString strSN )
{
    m_strSN = strSN;
}

void ProfileExtRec::setValue( QString strValue )
{
    m_strValue = strValue;
}
