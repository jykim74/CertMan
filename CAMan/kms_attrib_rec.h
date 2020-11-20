#ifndef KMSATTRIBREC_H
#define KMSATTRIBREC_H

#include <QString>

class KMSAttribRec
{
private:
    int         m_nNum;
    int         m_nType;
    QString     m_strValue;

public:
    KMSAttribRec();

    int getNum() { return m_nNum; };
    int getType() { return m_nType; };
    QString getValue() { return m_strValue; };

    void setNum( int nNum );
    void setType( int nType );
    void setValue( QString strValue );
};

#endif // KMSATTRIBREC_H
