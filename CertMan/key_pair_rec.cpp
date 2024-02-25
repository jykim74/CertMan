/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "key_pair_rec.h"

KeyPairRec::KeyPairRec()
{
    m_nNum = -1;
    m_nRegTime = 0;
    m_strAlg = "";
    m_strName = "";
    m_strPublicKey = "";
    m_strPrivateKey = "";
    m_strParam = "";
    m_nStatus = -1;
}

void KeyPairRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void KeyPairRec::setRegTime( int nRegTime )
{
    m_nRegTime = nRegTime;
}

void KeyPairRec::setAlg( QString strAlg )
{
    m_strAlg = strAlg;
}

void KeyPairRec::setName( QString strName )
{
    m_strName = strName;
}

void KeyPairRec::setPublicKey( QString strPublicKey )
{
    m_strPublicKey = strPublicKey;
}

void KeyPairRec::setPrivateKey( QString strPrivateKey )
{
    m_strPrivateKey = strPrivateKey;
}

void KeyPairRec::setParam( QString strParam )
{
    m_strParam = strParam;
}

void KeyPairRec::setStatus( int nStatus )
{
    m_nStatus = nStatus;
}
