#ifndef TSPREC_H
#define TSPREC_H

#include <QString>

class TSPRec
{
private:
    int         m_nSeq;
    int         m_nRegTime;
    int         m_nSerial;
    QString     m_strSrcHash;
    QString     m_strPolicy;
    QString     m_strTSTInfo;
    QString     m_strData;

public:
    TSPRec();

    int getSeq() { return m_nSeq; };
    int getRegTime() { return m_nRegTime; };
    int getSerial() { return m_nSerial; };
    QString getSrcHash() { return m_strSrcHash; };
    QString getPolicy() { return m_strPolicy; };
    QString getTSTInfo() { return m_strTSTInfo; };
    QString getData() { return m_strData; };

    void setSeq( int nSeq );
    void setRegTime( int nRegTime );
    void setSerial( int nSerial );
    void setSrcHash( const QString strSrcHash );
    void setPolicy( const QString strPolicy );
    void setTSTInfo( const QString strTSTInfo );
    void setData( const QString strData );
};

#endif // TSPREC_H
