#ifndef KEY_PAIR_REC_H
#define KEY_PAIR_REC_H

#include <QString>

class KeyPairRec
{
private:
    int             m_nNum;
    int             m_nRegTime;
    QString         m_strAlg;
    QString         m_strName;
    QString         m_strPublicKey;
    QString         m_strPrivateKey;
    QString         m_strParam;
    int             m_nStatus;

public:
    KeyPairRec();

    int getNum() { return m_nNum; };
    int getRegTime() { return m_nRegTime; };
    QString getAlg() { return m_strAlg; };
    QString getName() { return m_strName; };
    QString getPublicKey() { return m_strPublicKey; };
    QString getPrivateKey() { return m_strPrivateKey; };
    QString getParam() { return m_strParam; };
    int getStatus() { return m_nStatus; };

    void setNum( int nNum );
    void setRegTime( int nRegTime );
    void setAlg( QString strAlg );
    void setName( QString strName );
    void setPublicKey( QString strPublicKey );
    void setPrivateKey( QString strPrivateKey );
    void setParam( QString strParam );
    void setStatus( int nStatus );
};

#endif // KEY_PAIR_REC_H
