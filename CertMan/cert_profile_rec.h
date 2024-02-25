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
    long            m_uNotBefore;
    long            m_uNotAfter;
    int             m_nExtUsage;


public:
    CertProfileRec();

    int getNum() { return m_nNum; };
    QString getName() { return m_strName; };
    int getType() { return m_nType; };
    int getVersion() { return m_nVersion; };
    QString getHash() { return m_strHash; };
    QString getDNTemplate() { return m_strDNTemplate; };
    long getNotBefore() { return m_uNotBefore; };
    long getNotAfter() { return m_uNotAfter; };
    int getExtUsage() { return m_nExtUsage; };


    void setNum( int nNum );
    void setName( QString strName );
    void setType( int nType );
    void setVersion( int nVersion );
    void setHash( QString strHash );
    void setDNTemplate( QString strDNTemplate );
    void setNotBefore( long uNotBefore );
    void setNotAfter( long uNotAfter );
    void setExtUsage( int nExtUsage );

};

#endif // CERT_PROFILE_REC_H
