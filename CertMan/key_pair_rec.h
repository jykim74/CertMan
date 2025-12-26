/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef KEY_PAIR_REC_H
#define KEY_PAIR_REC_H

#include <QString>

class KeyPairRec
{
private:
    int             m_nNum;
    time_t          m_tRegTime;
    QString         m_strAlg;
    QString         m_strName;
    QString         m_strPublicKey;
    QString         m_strPrivateKey;
    QString         m_strParam;
    int             m_nStatus;

public:
    KeyPairRec();
    const QString getDesc();

    int getNum() { return m_nNum; };
    time_t getRegTime() { return m_tRegTime; };
    QString getAlg() { return m_strAlg; };
    QString getName() { return m_strName; };
    QString getPublicKey() { return m_strPublicKey; };
    QString getPrivateKey() { return m_strPrivateKey; };
    QString getParam() { return m_strParam; };
    int getStatus() { return m_nStatus; };

    void setNum( int nNum );
    void setRegTime( time_t tRegTime );
    void setAlg( QString strAlg );
    void setName( QString strName );
    void setPublicKey( QString strPublicKey );
    void setPrivateKey( QString strPrivateKey );
    void setParam( QString strParam );
    void setStatus( int nStatus );
};

#endif // KEY_PAIR_REC_H
