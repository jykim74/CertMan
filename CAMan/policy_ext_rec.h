#ifndef POLICY_EXT_REC_H
#define POLICY_EXT_REC_H

#include <QString>

class PolicyExtRec
{
private:
    int         m_nSeq;
    int         m_nPolicyNum;
    bool        m_bCritical;
    QString     m_strSN;
    QString     m_strValue;

public:
    PolicyExtRec();

    int getSeq() { return m_nSeq; };
    int getPolicyNum() { return m_nPolicyNum; };
    bool isCritical() { return m_bCritical; };
    QString getSN() { return m_strSN; };
    QString getValue() { return m_strValue; };

    void setSeq( int nSeq );
    void setPolicyNum( int nPolicyNum );
    void setCritical( bool bCritical );
    void setSN( QString strSN );
    void setValue( QString strValue );
};


#endif // POLICY_EXT_REC_H
