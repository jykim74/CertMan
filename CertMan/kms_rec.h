/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef KMSREC_H
#define KMSREC_H

#include <QString>

class KMSRec
{
private:
    int             m_nSeq;
    time_t          m_tRegTime;
    int             m_nState;
    int             m_nType;
    int             m_nAlgorithm;
    QString         m_strID;
    QString         m_strInfo;

public:
    KMSRec();

    int getSeq() { return m_nSeq; };
    time_t getRegTime() { return m_tRegTime; };
    int getState() { return m_nState; };
    int getType() { return m_nType; };
    int getAlgorithm() { return m_nAlgorithm; };
    QString getID() { return m_strID; };
    QString getInfo() { return m_strInfo; };


    void setSeq( int nSeq );
    void setRegTime( time_t tRegTime );
    void setState( int nState );
    void setType( int nType );
    void setAlgorithm( int nAlgorithm );
    void setID( QString strID );
    void setInfo( QString strInfo );
};

#endif // KMSREC_H
