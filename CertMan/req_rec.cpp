/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "req_rec.h"

ReqRec::ReqRec()
{
    m_nSeq = -1;
    m_tRegTime = 0;
    m_nKeyNum = -1;
    m_strName = "";
    m_strDN = "";
    m_strCSR = "";
    m_strHash = "";
    m_nStatus = -1;
}

void ReqRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void ReqRec::setRegTime( time_t tRegTime )
{
    m_tRegTime = tRegTime;
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
