/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "audit_rec.h"

AuditRec::AuditRec()
{
    m_nSeq = -1;
    m_nRegTime = 0;
    m_nKind = -1;
    m_nOperation = -1;

    m_strUserName = "";
    m_strInfo = "";
    m_strMAC = "";
}


void AuditRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void AuditRec::setRegTime( int nRegTime )
{
    m_nRegTime = nRegTime;
}

void AuditRec::setKind( int nKind )
{
    m_nKind = nKind;
}

void AuditRec::setOperation( int nOperation )
{
    m_nOperation = nOperation;
}

void AuditRec::setUserName( QString strUserName )
{
    m_strUserName = strUserName;
}

void AuditRec::setInfo( QString strInfo )
{
    m_strInfo = strInfo;
}

void AuditRec::setMAC( QString strMAC )
{
    m_strMAC = strMAC;
}
