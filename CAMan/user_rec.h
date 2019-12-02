#ifndef USERREC_H
#define USERREC_H

#include <QString>

class UserRec
{
private:
    int         m_nNum;
    QString     m_strName;
    QString     m_strSSN;
    QString     m_strEmail;
    int         m_nCertNum;
    int         m_nStatus;
    QString     m_strRefCode;
    QString     m_strSecretNum;

public:
    UserRec();

    int getNum() { return m_nNum; };
    QString getName() { return m_strName; };
    QString getSSN() { return m_strSSN; };
    QString getEmail() { return m_strEmail; };
    int getCertNum() { return m_nCertNum; };
    int getStatus() { return m_nStatus; };
    QString getRefCode() { return m_strRefCode; };
    QString getSecretNum() { return m_strSecretNum; };

    void setNum( int nNum );
    void setName( const QString strName );
    void setSSN( const QString strSSN );
    void setEmail( const QString strEmail );
    void setCertNum( int nCertNum );
    void setStatus( int nStatus );
    void setRefCode( const QString strRefCode );
    void setSecretNum( const QString strSecretNum );
};

#endif // USERREC_H
