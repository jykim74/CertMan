/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef REQ_REC_H
#define REQ_REC_H

#include <QString>

class ReqRec
{
private:
    int             m_nSeq;
    time_t          m_tRegTime;
    int             m_nKeyNum;
    QString         m_strName;
    QString         m_strDN;
    QString         m_strCSR;
    QString         m_strHash;
    int             m_nStatus;

public:
    ReqRec();

    int getSeq() { return m_nSeq; };
    time_t getRegTime() { return m_tRegTime; };
    int getKeyNum() { return m_nKeyNum; };
    QString getName() { return m_strName; };
    QString getDN() { return m_strDN; };
    QString getCSR() { return m_strCSR; };
    QString getHash() { return m_strHash; };
    int getStatus() { return m_nStatus; };

    void setSeq( int nSeq );
    void setRegTime( time_t tRegTime );
    void setKeyNum( int nKeyNum );
    void setName( QString strName );
    void setDN( QString strDN );
    void setCSR( QString strCSR );
    void setHash( QString strHash );
    void setStatus( int nStatus );
};

#endif // REQ_REC_H
