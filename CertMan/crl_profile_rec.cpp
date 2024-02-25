/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "crl_profile_rec.h"


CRLProfileRec::CRLProfileRec()
{
    m_nNum = -1;
    m_nVersion = -1;
    m_strName = "";
    m_strHash = "";
    m_tThisUpdate = -1;
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

void CRLProfileRec::setThisUpdate( time_t tThisUpdate )
{
    m_tThisUpdate = tThisUpdate;
}

void CRLProfileRec::setNextUpdate( time_t tNextUpdate )
{
    m_tNextUpdate = tNextUpdate;
}

