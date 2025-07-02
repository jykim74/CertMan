/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    time_t      m_tRegTime;
    int         m_nType;
    QString     m_strDN;
    QString     m_strDNHash;
    int         m_nStatus;
    QString     m_strCert;
    QString     m_strInfo;

public:
    SignerRec();

    int getNum() { return m_nNum; };
    time_t getRegTime() { return m_tRegTime; };
    int getType() { return m_nType; };
    QString getDN() { return m_strDN; };
    QString getDNHash() { return m_strDNHash; };
    int getStatus() { return m_nStatus; };
    QString getCert() { return m_strCert; };
    QString getInfo() { return m_strInfo; };

    void setNum( int nNum );
    void setRegTime( time_t tRegTime );
    void setType( int nType );
    void setDN( QString strDN );
    void setDNHash( QString strDNHash );
    void setStatus( int nStatus );
    void setCert( QString strCert );
    void setInfo( QString strInfo );
};

#endif // SIGNERREC_H
