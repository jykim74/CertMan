/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "user_rec.h"

UserRec::UserRec()
{
    m_nNum = -1;
    m_tRegTime = 0;
    m_strName = "";
    m_strSSN = "";
    m_strEmail = "";
    m_nStatus = -1;
    m_strRefNum = "";
    m_strAuthCode = "";
}

void UserRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void UserRec::setRegTime(time_t tRegTime)
{
    m_tRegTime = tRegTime;
}

void UserRec::setName( const QString strName )
{
    m_strName = strName;
}

void UserRec::setSSN( const QString strSSN )
{
    m_strSSN = strSSN;
}

void UserRec::setEmail(const QString strEmail)
{
    m_strEmail = strEmail;
}

void UserRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}

void UserRec::setRefNum( const QString strRefNum )
{
    m_strRefNum = strRefNum;
}

void UserRec::setAuthCode( const QString strAuthCode )
{
    m_strAuthCode = strAuthCode;
}
