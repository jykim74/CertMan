#include "admin_rec.h"

AdminRec::AdminRec()
{
    m_nSeq = -1;
    m_nStatus = -1;
    m_nType = -1;
    m_strName = "";
    m_strPassword = "";
    m_strEmail = "";
}

void AdminRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void AdminRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}

void AdminRec::setType( int nType )
{
    m_nType = nType;
}

void AdminRec::setName( const QString strName )
{
    m_strName = strName;
}

void AdminRec::setPassword( const QString strPassword )
{
    m_strPassword = strPassword;
}

void AdminRec::setEmail( const QString strEmail )
{
    m_strEmail = strEmail;
}
