#include "revoke_rec.h"

RevokeRec::RevokeRec()
{
    m_nSeq = -1;
    m_nCertNum = -1;
    m_nIssuerNum = -1;
    m_strSerial = "";
    m_nRevokeDate = -1;
}

void RevokeRec::setSeq( int nSeq )
{
    m_nSeq = nSeq;
}

void RevokeRec::setCertNum( int nCertNum )
{
    m_nCertNum = nCertNum;
}

void RevokeRec::setIssuerNum( int nIssuerNum )
{
    m_nIssuerNum = nIssuerNum;
}

void RevokeRec::setSerial( QString strSerial )
{
    m_strSerial = strSerial;
}

void RevokeRec::setRevokeDate( int nRevokeDate )
{
    m_nRevokeDate = nRevokeDate;
}

void RevokeRec::setReason( int nReason )
{
    m_nReason = nReason;
}
