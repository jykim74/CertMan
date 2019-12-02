#include "user_rec.h"

UserRec::UserRec()
{
    m_nNum = -1;
    m_strName = "";
    m_strSSN = "";
    m_strEmail = "";
    m_nCertNum = -1;
    m_nStatus = -1;
    m_strRefCode = "";
    m_strSecretNum = "";
}

void UserRec::setNum( int nNum )
{
    m_nNum = nNum;
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

void UserRec::setCertNum( int nCertNum )
{
    m_nCertNum = nCertNum;
}

void UserRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}

void UserRec::setRefCode( const QString strRefCode )
{
    m_strRefCode = strRefCode;
}

void UserRec::setSecretNum( const QString strSecretNum )
{
    m_strSecretNum = strSecretNum;
}
