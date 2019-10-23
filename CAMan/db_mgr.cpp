#include <QSqlQuery>
#include <QtSql>

#include "db_mgr.h"

DBMgr::DBMgr()
{

}

int DBMgr::open(const QString dbPath)
{
    db_ = QSqlDatabase::addDatabase( "QSQLITE" );
    db_.setDatabaseName( dbPath );

    if( !db_.open() )
    {
        return -1;
    }

    return 0;
}

void DBMgr::close()
{
    db_.close();
}
