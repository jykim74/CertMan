/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef USERREC_H
#define USERREC_H

#include <QString>

class UserRec
{
private:
    int         m_nNum;
    time_t      m_tRegTime;
    QString     m_strName;
    QString     m_strSSN;
    QString     m_strEmail;
    int         m_nStatus;
    QString     m_strRefNum;
    QString     m_strAuthCode;

public:
    UserRec();

    int getNum() { return m_nNum; };
    time_t getRegTime() { return m_tRegTime; };
    QString getName() { return m_strName; };
    QString getSSN() { return m_strSSN; };
    QString getEmail() { return m_strEmail; };
    int getStatus() { return m_nStatus; };
    QString getRefNum() { return m_strRefNum; };
    QString getAuthCode() { return m_strAuthCode; };

    void setNum( int nNum );
    void setRegTime( time_t tRegTime );
    void setName( const QString strName );
    void setSSN( const QString strSSN );
    void setEmail( const QString strEmail );
    void setStatus( int nStatus );
    void setRefNum( const QString strRefNum );
    void setAuthCode( const QString strAuthCode );
};

#endif // USERREC_H
