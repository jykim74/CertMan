#include "crl_rec.h"



CRLRec::CRLRec()
{

}

void CRLRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CRLRec::setIssuerNum( int nIssuerNum )
{
    m_nIssuerNum = nIssuerNum;
}

void CRLRec::setSignAlg( QString strSignAlg )
{
    m_strSignAlg = strSignAlg;
}

void CRLRec::setCRL( QString strCRL )
{
    m_strCRL = strCRL;
}
