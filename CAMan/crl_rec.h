#ifndef CRL_REC_H
#define CRL_REC_H

#include <QString>

class CRLRec
{
private:
    int             m_nNum;
    int             m_nRegTime;
    int             m_nIssuerNum;
    QString         m_strSignAlg;
    QString         m_strCRL;

public:
    CRLRec();

    int getNum() { return m_nNum; };
    int getRegTime() { return m_nRegTime; };
    int getIssuerNum() { return m_nIssuerNum; };
    QString getSignAlg() { return m_strSignAlg; };
    QString getCRL() { return m_strCRL; };

    void setNum( int nNum );
    void setRegTime( int nRegTime );
    void setIssuerNum( int nIssuerNum );
    void setSignAlg( QString strSignAlg );
    void setCRL( QString strCRL );
};

#endif // CRL_REC_H
