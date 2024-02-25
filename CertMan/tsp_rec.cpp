/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "tsp_rec.h"

TSPRec::TSPRec()
{
    m_nSeq = -1;
    m_nRegTime = 0;
    m_nSerial = -1;

    m_strSrcHash = "";
    m_strPolicy = "";
    m_strTSTInfo = "";
    m_strData = "";
}

void TSPRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void TSPRec::setRegTime( int nRegTime )
{
    m_nRegTime = nRegTime;
}

void TSPRec::setSerial( int nSerial )
{
    m_nSerial = nSerial;
}

void TSPRec::setSrcHash( const QString strSrcHash )
{
    m_strSrcHash = strSrcHash;
}

void TSPRec::setPolicy( const QString strPolicy )
{
    m_strPolicy = strPolicy;
}

void TSPRec::setTSTInfo( const QString strTSTInfo )
{
    m_strTSTInfo = strTSTInfo;
}

void TSPRec::setData( const QString strData )
{
    m_strData = strData;
}
