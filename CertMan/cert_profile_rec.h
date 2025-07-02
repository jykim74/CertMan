/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CERT_PROFILE_REC_H
#define CERT_PROFILE_REC_H

#include <QString>

class CertProfileRec
{
private:
    int             m_nNum;
    QString         m_strName;
    int             m_nType;
    int             m_nVersion;
    QString         m_strHash;
    QString         m_strDNTemplate;
    time_t          m_tNotBefore;
    time_t          m_tNotAfter;
    int             m_nExtUsage;


public:
    CertProfileRec();

    int getNum() { return m_nNum; };
    QString getName() { return m_strName; };
    int getType() { return m_nType; };
    int getVersion() { return m_nVersion; };
    QString getHash() { return m_strHash; };
    QString getDNTemplate() { return m_strDNTemplate; };
    time_t getNotBefore() { return m_tNotBefore; };
    time_t getNotAfter() { return m_tNotAfter; };
    int getExtUsage() { return m_nExtUsage; };


    void setNum( int nNum );
    void setName( QString strName );
    void setType( int nType );
    void setVersion( int nVersion );
    void setHash( QString strHash );
    void setDNTemplate( QString strDNTemplate );
    void setNotBefore( time_t tNotBefore );
    void setNotAfter( time_t tNotAfter );
    void setExtUsage( int nExtUsage );

};

#endif // CERT_PROFILE_REC_H
