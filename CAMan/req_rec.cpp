#include "req_rec.h"

ReqRec::ReqRec()
{

}

void ReqRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void ReqRec::setKeyNum( int nKeyNum )
{
    m_nKeyNum = nKeyNum;
}

void ReqRec::setName( QString strName )
{
    m_strName = strName;
}

void ReqRec::setDN( QString strDN )
{
    m_strDN = strDN;
}

void ReqRec::setCSR( QString strCSR )
{
    m_strCSR = strCSR;
}

void ReqRec::setHash( QString strHash )
{
    m_strHash = strHash;
}

void ReqRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}
