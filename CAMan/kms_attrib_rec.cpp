#include "kms_attrib_rec.h"

KMSAttribRec::KMSAttribRec()
{
    m_nNum = -1;
    m_nType = -1;
    m_strValue = "";
}

void KMSAttribRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void KMSAttribRec::setType( int nType )
{
    m_nType = nType;
}

void KMSAttribRec::setValue( QString strValue )
{
    m_strValue = strValue;
}
