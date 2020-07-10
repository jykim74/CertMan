#ifndef KMSREC_H
#define KMSREC_H

#include <QString>

class KMSRec
{
private:
    int             m_nSeq;
    int             m_nRegTime;
    int             m_nStatus;
    int             m_nType;
    QString         m_strID;
    QString         m_strInfo;

public:
    KMSRec();

    int getSeq() { return m_nSeq; };
    int getRegTime() { return m_nRegTime; };
    int getStatus() { return m_nStatus; };
    int getType() { return m_nType; };
    QString getID() { return m_strID; };
    QString getInfo() { return m_strInfo; };


    void setSeq( int nSeq );
    void setRegTime( int nRegTime );
    void setStatus( int nStatus );
    void setType( int nType );
    void setID( QString strID );
    void setInfo( QString strInfo );
};

#endif // KMSREC_H
