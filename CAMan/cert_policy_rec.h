#ifndef CERT_POLICY_REC_H
#define CERT_POLICY_REC_H

#include <QString>

class CertPolicyRec
{
private:
    int             m_nNum;
    QString         m_strName;
    int             m_nVersion;
    QString         m_strHash;
    QString         m_strDNTemplate;
    long            m_uNotBefore;
    long            m_uNotAfter;
    int             m_nDivideNum;

public:
    CertPolicyRec();

    int getNum() { return m_nNum; };
    QString getName() { return m_strName; };
    int getVersion() { return m_nVersion; };
    QString getHash() { return m_strHash; };
    QString getDNTemplate() { return m_strDNTemplate; };
    long getNotBefore() { return m_uNotBefore; };
    long getNotAfter() { return m_uNotAfter; };
    int getDivideNum() { return m_nDivideNum; };

    void setNum( int nNum );
    void setName( QString strName );
    void setVersion( int nVersion );
    void setHash( QString strHash );
    void setDNTemplate( QString strDNTemplate );
    void setNotBefore( long uNotBefore );
    void setNotAfter( long uNotAfter );
    void setDivideNum( int nDivideNum );
};

#endif // CERT_POLICY_REC_H
