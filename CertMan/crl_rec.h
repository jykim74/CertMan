/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CRL_REC_H
#define CRL_REC_H

#include <QString>

class CRLRec
{
private:
    int             m_nNum;
    time_t          m_tRegTime;
    int             m_nIssuerNum;
    time_t          m_tThisUpdate;
    time_t          m_tNextUpdate;
    QString         m_strSignAlg;
    QString         m_strCRLDP;
    QString         m_strCRL;

public:
    CRLRec();

    int getNum() { return m_nNum; };
    time_t getRegTime() { return m_tRegTime; };
    int getIssuerNum() { return m_nIssuerNum; };
    time_t getThisUpdate() { return m_tThisUpdate; };
    time_t getNextUpdate() { return m_tNextUpdate; };
    QString getSignAlg() { return m_strSignAlg; };
    QString getCRLDP() { return m_strCRLDP; };
    QString getCRL() { return m_strCRL; };

    void setNum( int nNum );
    void setRegTime( time_t tRegTime );
    void setIssuerNum( int nIssuerNum );
    void setThisUpdate( time_t tThisUpdate );
    void setNextUpdate( time_t tNextUpdate );
    void setSignAlg( QString strSignAlg );
    void setCRLDP( QString strCRLDP );
    void setCRL( QString strCRL );
};

#endif // CRL_REC_H
