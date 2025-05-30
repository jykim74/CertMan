/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "crl_rec.h"



CRLRec::CRLRec()
{
    m_nNum = -1;
    m_nRegTime = 0;
    m_nIssuerNum = -1;
    m_nThisUpdate = -1;
    m_nNextUpdate = -1;
    m_strCRL = "";
    m_strCRLDP = "";
}

void CRLRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CRLRec::setRegTime(int nRegTime)
{
    m_nRegTime = nRegTime;
}

void CRLRec::setIssuerNum( int nIssuerNum )
{
    m_nIssuerNum = nIssuerNum;
}

void CRLRec::setThisUpdate( int nThisUpdate )
{
    m_nThisUpdate = nThisUpdate;
}

void CRLRec::setNextUpdate( int nNextUpdate )
{
    m_nNextUpdate = nNextUpdate;
}

void CRLRec::setSignAlg( QString strSignAlg )
{
    m_strSignAlg = strSignAlg;
}

void CRLRec::setCRL( QString strCRL )
{
    m_strCRL = strCRL;
}

void CRLRec::setCRLDP(QString strCRLDP)
{
    m_strCRLDP = strCRLDP;
}
