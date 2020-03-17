#ifndef REVOKE_REC_H
#define REVOKE_REC_H

#include <QString>

class RevokeRec
{
private:
    int         m_nSeq;
    int         m_nCertNum;
    int         m_nIssuerNum;
    QString     m_strSerial;
    int         m_nRevokeDate;
    int         m_nReason;
    QString     m_strCRLDP;

public:
    RevokeRec();

    int getSeq() { return m_nSeq; };
    int getCertNum() { return m_nCertNum; };
    int getIssuerNum() { return m_nIssuerNum; };
    QString getSerial() { return m_strSerial; };
    int getRevokeDate() { return m_nRevokeDate; };
    int getReason() { return m_nReason; };
    QString getCRLDP() { return m_strCRLDP; };

    void setSeq( int nSeq );
    void setCertNum( int nCertNum );
    void setIssuerNum( int nIssuerNum );
    void setSerial( QString strSerial );
    void setRevokeDate( int nRevokeDate );
    void setReason( int nReason );
    void setCRLDP( QString strCRLDP );
};

#endif // REVOKE_REC_H
