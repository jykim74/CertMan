/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef PROFILE_EXT_REC_H
#define PROFILE_EXT_REC_H

#include <QString>

class ProfileExtRec
{
private:
    int         m_nSeq;
    int         m_nProfileNum;
    bool        m_bCritical;
    QString     m_strSN;
    QString     m_strValue;

public:
    ProfileExtRec();

    int getSeq() { return m_nSeq; };
    int getProfileNum() { return m_nProfileNum; };
    bool isCritical() { return m_bCritical; };
    const QString getSN() { return m_strSN; };
    const QString getValue() { return m_strValue; };

    void setSeq( int nSeq );
    void setProfileNum( int nProfileNum );
    void setCritical( bool bCritical );
    void setSN( QString strSN );
    void setValue( QString strValue );
};


#endif // PROFILE_EXT_REC_H
