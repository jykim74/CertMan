/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "signer_rec.h"

SignerRec::SignerRec()
{
    m_nNum = -1;
    m_tRegTime = 0;
    m_nType = 0;
    m_strDN = "";
    m_strDNHash = "";
    m_nStatus = -1;
    m_strCert = "";
    m_strInfo = "";
}

void SignerRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void SignerRec::setRegTime(time_t tRegTime)
{
    m_tRegTime = tRegTime;
}

void SignerRec::setType( int nType )
{
    m_nType = nType;
}

void SignerRec::setDN( QString strDN )
{
    m_strDN = strDN;
}

void SignerRec::setDNHash(QString strDNHash)
{
    m_strDNHash = strDNHash;
}

void SignerRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}

void SignerRec::setCert( QString strCert )
{
    m_strCert = strCert;
}

void SignerRec::setInfo( QString strInfo )
{
    m_strInfo = strInfo;
}
