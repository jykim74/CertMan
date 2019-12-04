#ifndef CERT_REC_H
#define CERT_REC_H


#include <QString>

class CertRec
{
private:
    int         m_nNum;
    int         m_nKeyNum;
    QString     m_strSignAlg;
    QString     m_strCert;
    bool        m_bSelf;
    bool        m_bCA;
    int         m_nIssuerNum;
    QString     m_strSubjectDN;
    int         m_nStatus;
    QString     m_strSerial;
    QString     m_strDNHash;
    QString     m_strKeyHash;

public:
    CertRec();

    int getNum() { return m_nNum; };
    int getKeyNum() { return m_nKeyNum; };
    QString getSignAlg() { return m_strSignAlg; };
    QString getCert() { return m_strCert; };
    bool isSelf() { return m_bSelf; };
    bool isCA() { return m_bCA; };
    int getIssuerNum() { return m_nIssuerNum; };
    QString getSubjectDN() { return m_strSubjectDN; };
    int getStatus() { return m_nStatus; };
    QString getSerial() { return m_strSerial; };
    QString getDNHash() { return m_strDNHash; };
    QString getKeyHash() { return m_strKeyHash; };

    void setNum( int nNum );
    void setKeyNum( int nKeyNum );
    void setSignAlg( QString strSignAlg );
    void setCert( QString strCert );
    void setSelf( bool bSelf );
    void setCA( bool bCA );
    void setIssuerNum( int nIssuerNum );
    void setSubjectDN( QString strSubjectDN );
    void setStatus( int nStatus );
    void setSerial( QString strSerial );
    void setDNHash( QString strDNHash );
    void setKeyHash( QString strKeyHash );
};


#endif // CERT_REC_H
