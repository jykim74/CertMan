/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef AUDITREC_H
#define AUDITREC_H

#include <QString>

class AuditRec
{
private:
    int         m_nSeq;
    int         m_tRegTime;
    int         m_nKind;
    int         m_nOperation;
    QString     m_strUserName;
    QString     m_strInfo;
    QString     m_strMAC;

public:
    AuditRec();

    int getSeq() { return m_nSeq; };
    time_t getRegTime() { return m_tRegTime; };
    int getKind() { return m_nKind; };
    int getOperation() { return m_nOperation; };
    QString getUserName() { return m_strUserName; };
    QString getInfo() { return m_strInfo; };
    QString getMAC() { return m_strMAC; };

    void setSeq( int nSeq );
    void setRegTime( time_t tRegTime );
    void setKind( int nKind );
    void setOperation( int nOperation );
    void setUserName( QString strUserName );
    void setInfo( QString strInfo );
    void setMAC( QString strMAC );
};

#endif // AUDITREC_H
