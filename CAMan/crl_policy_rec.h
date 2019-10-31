#ifndef CRL_POLICY_REC_H
#define CRL_POLICY_REC_H

#include <QString>

class CRLPolicyRec
{
private:
    int             m_nNum;
    int             m_nVersion;
    QString         m_strName;
    QString         m_strHash;
    time_t          m_tLastUpdate;
    time_t          m_tNextUpdate;

public:
    CRLPolicyRec();

    int getNum() { return m_nNum; };
    int getVersion() { return m_nVersion; };
    QString getName() { return m_strName; };
    QString getHash() { return m_strHash; };
    time_t getLastUpdate() { return m_tLastUpdate; };
    time_t getNextUpdate() { return m_tNextUpdate; };

    void setNum( int nNum );
    void setVersion( int nVersion );
    void setName( QString strName );
    void setHash( QString strHash );
    void setLastUpdate( time_t tLastUpdate );
    void setNextUpdate( time_t tNextUpdate );
};

#endif // CRL_POLICY_REC_H
