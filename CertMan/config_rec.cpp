/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "config_rec.h"

ConfigRec::ConfigRec()
{
    m_nNum = -1;
    m_nKind = -1;

    m_strName = "";
    m_strValue = "";
}

void ConfigRec::setNum( int nNum )
{
    m_nNum = nNum;
}

void ConfigRec::setKind( int nKind )
{
    m_nKind = nKind;
}

void ConfigRec::setName( QString strName )
{
    m_strName = strName;
}

void ConfigRec::setValue( QString strValue )
{
    m_strValue = strValue;
}
