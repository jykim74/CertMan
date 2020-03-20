#include "signer_rec.h"

SignerRec::SignerRec()
{
    m_nNum = -1;
    m_nRegTime = 0;
    m_nType = 0;
    m_strDN = "";
    m_strDNHash = "";
    m_nStatus = -1;
    m_strCert = "";
    m_strDesc = "";
}

void SignerRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void SignerRec::setRegTime(int nRegTime)
{
    m_nRegTime = nRegTime;
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

void SignerRec::setDesc( QString strDesc )
{
    m_strDesc = strDesc;
}
