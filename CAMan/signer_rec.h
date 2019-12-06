#ifndef SIGNERREC_H
#define SIGNERREC_H

#include <QString>

enum {
    SIGNER_TYPE_REG = 0,
    SIGNER_TYPE_OCSP
};

class SignerRec
{
private:
    int         m_nNum;
    int         m_nType;
    QString     m_strDN;
    QString     m_strDNHash;
    int         m_nStatus;
    QString     m_strCert;
    QString     m_strDesc;

public:
    SignerRec();

    int getNum() { return m_nNum; };
    int getType() { return m_nType; };
    QString getDN() { return m_strDN; };
    QString getDNHash() { return m_strDNHash; };
    int getStatus() { return m_nStatus; };
    QString getCert() { return m_strCert; };
    QString getDesc() { return m_strDesc; };

    void setNum( int nNum );
    void setType( int nType );
    void setDN( QString strDN );
    void setDNHash( QString strDNHash );
    void setStatus( int nStatus );
    void setCert( QString strCert );
    void setDesc( QString strDesc );
};

#endif // SIGNERREC_H
