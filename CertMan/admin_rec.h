#ifndef ADMINREC_H
#define ADMINREC_H

#include <QString>

class AdminRec
{
private:
    int         m_nSeq;
    int         m_nStatus;
    int         m_nType;
    QString     m_strName;
    QString     m_strPassword;
    QString     m_strEmail;

public:
    AdminRec();

    int getSeq() { return m_nSeq; };
    int getStatus() { return m_nStatus; };
    int getType() { return m_nType; };
    QString getName() { return m_strName; };
    QString getPassword() { return m_strPassword; };
    QString getEmail() { return m_strEmail; };

    void setSeq( int nSeq );
    void setStatus( int nStatus );
    void setType( int nType );
    void setName( const QString strName );
    void setPassword( const QString strPassword );
    void setEmail( const QString strEmail );
};

#endif // ADMINREC_H
