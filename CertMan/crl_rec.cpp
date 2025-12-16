/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "crl_rec.h"
#include "commons.h"

CRLRec::CRLRec()
{
    m_nNum = -1;
    m_tRegTime = 0;
    m_nIssuerNum = -1;
    m_tThisUpdate = 0;
    m_tNextUpdate = 0;
    m_strCRL = "";
    m_strCRLDP = "";
}

void CRLRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void CRLRec::setRegTime(time_t tRegTime)
{
    m_tRegTime = tRegTime;
}

void CRLRec::setIssuerNum( int nIssuerNum )
{
    m_nIssuerNum = nIssuerNum;
}

void CRLRec::setThisUpdate( time_t tThisUpdate )
{
    m_tThisUpdate = tThisUpdate;
}

void CRLRec::setNextUpdate( time_t tNextUpdate )
{
    m_tNextUpdate = tNextUpdate;
}

void CRLRec::setSignAlg( QString strSignAlg )
{
    m_strSignAlg = strSignAlg;
}

void CRLRec::setCRL( QString strCRL )
{
    m_strCRL = strCRL;
}

void CRLRec::setCRLDP(QString strCRLDP)
{
    m_strCRLDP = strCRLDP;
}

const QIcon CRLRec::getIcon( time_t now_t )
{
    if( m_nIssuerNum == kImportNum )
    {
        if( m_tNextUpdate < now_t )
            return QIcon( ":/images/im_crl_expired.png" );
        else
            return QIcon( ":/images/im_crl.png" );
    }

    if( m_tNextUpdate < now_t )
        return QIcon( ":/images/crl_expired.png" );

    return QIcon( ":/images/crl.png" );
}
