#ifndef CONFIGREC_H
#define CONFIGREC_H

#include <QString>

class ConfigRec
{
private:
    int         m_nNum;
    int         m_nKind;
    QString     m_strName;
    QString     m_strValue;

public:
    ConfigRec();

    int getNum() { return m_nNum; };
    int getKind() { return m_nKind; };
    QString getName() { return m_strName; };
    QString getValue() { return m_strValue; };

    void setNum( int nNum );
    void setKind( int nKind );
    void setName( QString strName );
    void setValue( QString strValue );
};

#endif // CONFIGREC_H
