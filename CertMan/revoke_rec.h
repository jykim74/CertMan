/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    time_t      m_tRevokeDate;
    int         m_nReason;
    QString     m_strCRLDP;

public:
    RevokeRec();

    int getSeq() { return m_nSeq; };
    int getCertNum() { return m_nCertNum; };
    int getIssuerNum() { return m_nIssuerNum; };
    QString getSerial() { return m_strSerial; };
    time_t getRevokeDate() { return m_tRevokeDate; };
    int getReason() { return m_nReason; };
    QString getCRLDP() { return m_strCRLDP; };

    void setSeq( int nSeq );
    void setCertNum( int nCertNum );
    void setIssuerNum( int nIssuerNum );
    void setSerial( QString strSerial );
    void setRevokeDate( time_t tRevokeDate );
    void setReason( int nReason );
    void setCRLDP( QString strCRLDP );
};

#endif // REVOKE_REC_H
