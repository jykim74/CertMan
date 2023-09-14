#ifndef CRL_PROFILE_REC_H
#define CRL_PROFILE_REC_H

#include <QString>

class CRLProfileRec
{
private:
    int             m_nNum;
    int             m_nVersion;
    QString         m_strName;
    QString         m_strHash;
    time_t          m_tThisUpdate;
    time_t          m_tNextUpdate;

public:
    CRLProfileRec();

    int getNum() { return m_nNum; };
    int getVersion() { return m_nVersion; };
    QString getName() { return m_strName; };
    QString getHash() { return m_strHash; };
    time_t getThisUpdate() { return m_tThisUpdate; };
    time_t getNextUpdate() { return m_tNextUpdate; };

    void setNum( int nNum );
    void setVersion( int nVersion );
    void setName( QString strName );
    void setHash( QString strHash );
    void setThisUpdate( time_t tThisUpdate );
    void setNextUpdate( time_t tNextUpdate );
};

#endif // CRL_PROFILE_REC_H
