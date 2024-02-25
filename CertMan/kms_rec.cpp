/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "kms_rec.h"

KMSRec::KMSRec()
{
    m_nSeq = -1;
    m_nRegTime = -1;
    m_nState = -1;
    m_nType = -1;
    m_nAlgorithm = -1;

    m_strID = "";
    m_strInfo = "";
}


void KMSRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void KMSRec::setRegTime( int nRegTime )
{
    m_nRegTime = nRegTime;
}

void KMSRec::setState( int nState )
{
    m_nState = nState;
}

void KMSRec::setType( int nType )
{
    m_nType = nType;
}

void KMSRec::setAlgorithm(int nAlgorithm)
{
    m_nAlgorithm = nAlgorithm;
}

void KMSRec::setID( QString strID )
{
    m_strID = strID;
}

void KMSRec::setInfo( QString strInfo )
{
    m_strInfo = strInfo;
}
