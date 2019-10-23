#ifndef DB_MGR_H
#define DB_MGR_H

#include <QtSql/QSqlDatabase>

class DBMgr
{
public:
    DBMgr();

    int open( const QString dbPath );
    void close();

private:
    QSqlDatabase   db_;
};

#endif // DB_MGR_H
