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
    int             m_nAlgorithm;
    QString         m_strID;
    QString         m_strInfo;

public:
    KMSRec();

    int getSeq() { return m_nSeq; };
    int getRegTime() { return m_nRegTime; };
    int getStatus() { return m_nStatus; };
    int getType() { return m_nType; };
    int getAlgorithm() { return m_nAlgorithm; };
    QString getID() { return m_strID; };
    QString getInfo() { return m_strInfo; };


    void setSeq( int nSeq );
    void setRegTime( int nRegTime );
    void setStatus( int nStatus );
    void setType( int nType );
    void setAlgorithm( int nAlgorithm );
    void setID( QString strID );
    void setInfo( QString strInfo );
};

#endif // KMSREC_H
