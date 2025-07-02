/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "cert_profile_rec.h"

CertProfileRec::CertProfileRec()
{
    m_nNum = -1;
    m_nType = -1;
    m_nVersion = -1;
    m_tNotBefore = -1;
    m_tNotAfter = -1;
    m_nExtUsage = -1;
    m_strName = "";
    m_strHash = "";
    m_strDNTemplate = "";
}

void CertProfileRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CertProfileRec::setName( QString strName )
{
    m_strName = strName;
}

void CertProfileRec::setType( int nType )
{
    m_nType = nType;
}

void CertProfileRec::setVersion( int nVersion )
{
    m_nVersion = nVersion;
}

void CertProfileRec::setHash( QString strHash )
{
    m_strHash = strHash;
}

void CertProfileRec::setDNTemplate( QString strDNTemplate )
{
    m_strDNTemplate = strDNTemplate;
}

void CertProfileRec::setNotBefore( time_t tNotBefore )
{
    m_tNotBefore = tNotBefore;
}

void CertProfileRec::setNotAfter( time_t tNotAfter )
{
    m_tNotAfter = tNotAfter;
}

void CertProfileRec::setExtUsage( int nExtUsage )
{
    m_nExtUsage = nExtUsage;
}
