#include "key_pair_rec.h"

KeyPairRec::KeyPairRec()
{

}

void KeyPairRec::setNum( int nNum )
{
    m_nNum = nNum;
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
