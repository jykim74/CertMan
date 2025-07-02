/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CERT_REC_H
#define CERT_REC_H


#include <QString>

class CertRec
{
private:
    int         m_nNum;
    time_t      m_tRegTime;
    int         m_nKeyNum;
    int         m_nUserNum;
    QString     m_strSignAlg;
    QString     m_strCert;
    int         m_nSelf;
    int         m_nCA;
    int         m_nIssuerNum;
    QString     m_strSubjectDN;
    int         m_nStatus;
    QString     m_strSerial;
    QString     m_strDNHash;
    QString     m_strKeyHash;
    QString     m_strCRLDP;

public:
    CertRec();

    int getNum() { return m_nNum; };
    time_t getRegTime() { return m_tRegTime; };
    int getKeyNum() { return m_nKeyNum; };
    int getUserNum() { return m_nUserNum; };
    QString getSignAlg() { return m_strSignAlg; };
    QString getCert() { return m_strCert; };
    int isSelf() { return m_nSelf; };
    int isCA() { return m_nCA; };
    int getIssuerNum() { return m_nIssuerNum; };
    QString getSubjectDN() { return m_strSubjectDN; };
    int getStatus() { return m_nStatus; };
    QString getSerial() { return m_strSerial; };
    QString getDNHash() { return m_strDNHash; };
    QString getKeyHash() { return m_strKeyHash; };
    QString getCRLDP() { return m_strCRLDP; };

    void setNum( int nNum );
    void setRegTime( time_t tRegTime );
    void setKeyNum( int nKeyNum );
    void setUserNum( int nUserNum );
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
    void setCRLDP( QString strCRLDP );
};


#endif // CERT_REC_H
