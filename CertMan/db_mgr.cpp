#include <QSqlQuery>
#include <QtSql>
#include <iostream>

#include "db_mgr.h"
#include "cert_rec.h"
#include "cert_profile_rec.h"
#include "crl_rec.h"
#include "crl_profile_rec.h"
#include "key_pair_rec.h"
#include "profile_ext_rec.h"
#include "req_rec.h"
#include "revoke_rec.h"
#include "user_rec.h"
#include "signer_rec.h"
#include "kms_rec.h"
#include "kms_attrib_rec.h"
#include "audit_rec.h"
#include "tsp_rec.h"
#include "admin_rec.h"
#include "config_rec.h"

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

    if( db_.isOpen() == false )
        return -1;

    db_type_ = "QSQLITE";
    return 0;
}

int DBMgr::remoteOpen( const QString strType, const QString strHost, const QString strUserName, const QString strPasswd, const QString strDBName )
{
    int nPort = -1;
    QString strDBHost;
    QStringList hostList = strHost.split( ":" );

    if( hostList.size() < 1 ) return -1;

    strDBHost = hostList.at(0);
    if( hostList.size() > 1 )
        nPort = hostList.at(1).toInt();

    if( nPort < 0 )
    {
        if( strType == "QMYSQL" || strType == "QMYSQL3" || strType == "QMARIADB" )
            nPort = 3306;
        else if( strType == "QPSQL" || strType == "QPSQL7" )
            nPort = 5432;
        else if( strType == "QODBC" || strType == "QODBC3" )
            nPort = 1433;
    }

    if( nPort < 0 ) return -2;


    db_ = QSqlDatabase::addDatabase( strType );
    db_.setHostName( strDBHost );
    db_.setPort( nPort );
    db_.setDatabaseName( strDBName );
    db_.setUserName( strUserName );
    db_.setPassword( strPasswd );

    if( !db_.open() )
    {
        return -3;
    }

    if( db_.isOpen() == false )
        return -4;

    db_type_ = strType;
    return 0;
}

void DBMgr::close()
{
    db_.close();
    db_type_.clear();
}

bool DBMgr::isOpen()
{
    return db_.isOpen();
}

QString DBMgr::getNumName( int nNum, QString strTable, QString strColName )
{
    QString strName;
    if( nNum < 0 ) return strName;

    QString strSQL = QString( "SELECT %1 FROM %2 WHERE NUM = %3").arg( strColName ).arg( strTable ).arg(nNum);
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        strName = SQL.value(0).toString();
        break;
    }

    return strName;
}

/*
QString DBMgr::getSeqName( int nSeq, QString strTable, QString strColName )
{
    QString strName;
    if( nSeq < 0 ) return "Unknown";

    QString strSQL = QString( "SELECT %1 FROM %2 WHERE SEQ = %3").arg( strColName ).arg( strTable ).arg(nSeq);
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        strName = SQL.value(0).toString();
        break;
    }

    return strName;
}
*/

int DBMgr::_getCertList( QString strQuery, QList<CertRec>& certList )
{
    int     iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "Num" );
    int nPosRegTime = SQL.record().indexOf( "RegTime" );
    int nPosKeyNum = SQL.record().indexOf( "KeyNum" );
    int nPosUserNum = SQL.record().indexOf( "UserNum" );
    int nPosSignAlg = SQL.record().indexOf( "SignAlg" );
    int nPosCert = SQL.record().indexOf( "CERT" );
    int nPosSelf = SQL.record().indexOf( "IsSelf" );
    int nPosCA = SQL.record().indexOf( "IsCA" );
    int nPosIssuerNum = SQL.record().indexOf( "IssuerNum" );
    int nPosSubjectDN = SQL.record().indexOf( "SubjectDN" );
    int nPosStatus = SQL.record().indexOf( "Status" );
    int nPosSerial = SQL.record().indexOf( "Serial" );
    int nPosDNHash = SQL.record().indexOf( "DNHash" );
    int nPosKeyHash = SQL.record().indexOf( "KeyHash" );
    int nPosCRLDP = SQL.record().indexOf( "CRLDP" );

    while( SQL.next() )
    {
        CertRec certRec;

        certRec.setNum( SQL.value(nPosNum).toInt() );
        certRec.setRegTime( SQL.value(nPosRegTime).toInt());
        certRec.setKeyNum( SQL.value(nPosKeyNum).toInt());
        certRec.setUserNum( SQL.value( nPosUserNum ).toInt());
        certRec.setSignAlg( SQL.value(nPosSignAlg).toString() );
        certRec.setCert( SQL.value(nPosCert).toString() );
        certRec.setSelf( SQL.value(nPosSelf).toBool() );
        certRec.setCA( SQL.value(nPosCA).toBool() );
        certRec.setIssuerNum( SQL.value(nPosIssuerNum).toInt());
        certRec.setSubjectDN( SQL.value(nPosSubjectDN).toString() );
        certRec.setStatus( SQL.value(nPosStatus).toInt());
        certRec.setSerial( SQL.value(nPosSerial).toString() );
        certRec.setDNHash( SQL.value(nPosDNHash).toString() );
        certRec.setKeyHash( SQL.value(nPosKeyHash).toString() );
        certRec.setCRLDP( SQL.value(nPosCRLDP).toString());

        certList.append( certRec );
        iCount++;
    }

    SQL.finish();

    if( iCount == 0 ) return -1;

    return 0;
}

int DBMgr::getCertCountAll()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CERT" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCRLCountAll()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CRL" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getKeyPairCountAll()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_KEY_PAIR" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getReqCountAll()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_REQ" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCertCount( int nIssuerNum )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CERT WHERE ISSUERNUM = %1").arg( nIssuerNum );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCACount()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CERT WHERE ISCA = 1");
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCRLCount( int nIssuerNum )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CRL WHERE ISSUERNUM = %1").arg( nIssuerNum );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getKeyPairCount( int nStatus )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_KEY_PAIR" );
    if( nStatus >= 0 ) strSQL += QString( " WHERE STATUS = %1" ).arg( nStatus );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getReqCount( int nStatus )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_REQ" );
    if( nStatus >= 0 ) strSQL += QString( " WHERE STATUS = %1" ).arg( nStatus );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getRevokeCount( int nIssuerNum )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_REVOKED WHERE ISSUERNUM = %1").arg( nIssuerNum );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getUserCount()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_USER" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getKMSCount()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_KMS" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getAuditCount()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_AUDIT" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getTSPCount()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_TSP" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCertProfileCount( int nType )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CERT_PROFILE" );

    if( nType >= 0 )
        strSQL += QString( " WHERE TYPE = %1" ).arg( nType );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCRLProfileCount()
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CRL_PROFILE" );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getStatisticsCount( int nStartTime, int nEndTime, QString strTable )
{
    int nCount = -1;

    QString strTime = "REGTIME";
    QString strSQL = QString( "SELECT COUNT(*) FROM %1" ).arg( strTable );

    if( strTable == "TB_REVOKED" )
        strTime = "REVOKEDDATE";

    if( nStartTime >= 0 || nEndTime >= 0 )
    {
        strSQL += " WHERE ";

        if( nStartTime >= 0  && nEndTime >= 0 )
            strSQL += QString( "%1 >= %2 AND %3 <= %4" ).arg(strTime).arg( nStartTime ).arg(strTime).arg( nEndTime );
        else if( nStartTime >= 0 )
            strSQL += QString( "%1 >= %2" ).arg(strTime).arg( nStartTime );
        else if( nEndTime >= 0 )
            strSQL += QString( "%1 <= %2" ).arg(strTime).arg( nEndTime );
    }

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCertSearchCount( int nIssuerNum, QString strTarget, QString strWord )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CERT WHERE ISSUERNUM = %1" )
            .arg( nIssuerNum );

    if( strTarget != nullptr && strTarget.length() > 1 )
    {
        strSQL += QString( " AND %1 LIKE '%%2%'" ).arg( strTarget ).arg( strWord );
    }

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCRLSearchCount( int nIssuerNum, QString strTarget, QString strWord )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CRL WHERE ISSUERNUM = %1" )
            .arg( nIssuerNum );

    if( strTarget != nullptr && strTarget.length() > 1 )
    {
        strSQL += QString( " AND %1 LIKE '%%2%'" ).arg( strTarget ).arg( strWord );
    }

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getKeyPairSearchCount( int nStatus, QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_KEY_PAIR WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    if( nStatus >= 0 ) strSQL += QString( " AND STATUS = %1" ).arg( nStatus );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getReqSearchCount( int nStatus, QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_REQ WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    if( nStatus >= 0 ) strSQL += QString( " AND STATUS = %1" ).arg( nStatus );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getRevokeSearchCount( int nIssuerNum, QString strTarget, QString strWord )
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_REVOKED WHERE ISSUERNUM = %1 AND %2 LIKE '%%3%'")
            .arg( nIssuerNum )
            .arg( strTarget )
            .arg( strWord );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getUserSearchCount( QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_USER WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getKMSSearchCount( QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_KMS WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getAuditSearchCount( QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_AUDIT WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getTSPSearchCount( QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_TSP WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getCACertList( QList<CertRec>& certList )
{
    QString strSQL  = "SELECT * FROM TB_CERT WHERE ISCA=1 ORDER BY NUM DESC";

    return _getCertList( strSQL, certList );
}

int DBMgr::getIssuerCertList( QList<CertRec>& certList )
{
    QString strSQL  = "SELECT * FROM TB_CERT WHERE ISCA=1 AND ISSUERNUM >= -1 ORDER BY NUM DESC";

    return _getCertList( strSQL, certList );
}

int DBMgr::getCACertList( int nIssuerNum, QList<CertRec>& certList )
{
    QString strSQL  = QString( "SELECT * FROM TB_CERT "
                               "WHERE ISCA=1 AND ISSUERNUM = %1 ORDER BY NUM DESC").arg( nIssuerNum );

    return _getCertList( strSQL, certList );
}

int DBMgr::getCACertList( int nIssuerNum, QString strTarget, QString strWord, QList<CertRec>& certList )
{
    QString strSQL  = QString( "SELECT * FROM TB_CERT "
                               "WHERE ISCA=1 AND ISSUERNUM = %1 AND %2 LIKE '%%3%' "
                               "ORDER BY NUM DESC")
            .arg( nIssuerNum )
            .arg( strTarget )
            .arg( strWord );

    return _getCertList( strSQL, certList );
}

int DBMgr::getCertRec( int nNum, CertRec& cert )
{
    QList<CertRec> certList;
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_CERT WHERE NUM = %1").arg( nNum );

    _getCertList( strSQL, certList );
    if( certList.size() <= 0 ) return -1;

    cert = certList.at(0);
    return 0;
}

int DBMgr::getCertList( int nIssuerNum, QList<CertRec>& certList )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_CERT WHERE ISSUERNUM = %1 ORDER BY NUM DESC" ).arg( nIssuerNum );

    return _getCertList( strSQL, certList );
}

int DBMgr::getCertList( int nIssuerNum, int nOffset, int nLimit, QList<CertRec>& certList )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_CERT WHERE ISSUERNUM = %1 "
                      "ORDER BY NUM DESC LIMIT %2 OFFSET %3" )
            .arg( nIssuerNum )
            .arg( nLimit )
            .arg( nOffset );

    return _getCertList( strSQL, certList );
}

int DBMgr::getCertList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<CertRec>& certList )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_CERT "
                      "WHERE ISSUERNUM = %1 AND %2 LIKE '%%3%' "
                      "ORDER BY NUM DESC LIMIT %4 OFFSET %5" )
            .arg( nIssuerNum )
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getCertList( strSQL, certList );
}

int DBMgr::getCertList( int nIssuerNum, QString strCRLDP, QList<CertRec>& certList )
{
    QString strSQL;
    strSQL = QString( "SELECT * FROM TB_CERT "
                      "WHERE ISSUERNUM = %1 AND CRLDP = '%2'" )
            .arg( nIssuerNum )
            .arg( strCRLDP );

    printf( "SQL : %s\n", strSQL.toStdString().c_str() );

    return _getCertList( strSQL, certList );
}

int DBMgr::getKeyPairList( int nStatus, QList<KeyPairRec>& keyPairList )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_KEY_PAIR" );

    if( nStatus >= 0 ) strSQL += QString( " WHERE STATUS = %1" ).arg( nStatus );

    strSQL += " ORDER BY NUM DESC";

    return _getKeyPairList( strSQL, keyPairList );
}

int DBMgr::getKeyPairList( int nStatus, int nOffset, int nLimit, QList<KeyPairRec>& keyPairList )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_KEY_PAIR" );

    if( nStatus >= 0 ) strSQL += QString( " WHERE STATUS = %1" ).arg( nStatus );

    strSQL += QString( " ORDER BY NUM DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getKeyPairList( strSQL, keyPairList );
}

int DBMgr::getKeyPairList( int nStatus, QString strTarget, QString strWord, int nOffset, int nLimit, QList<KeyPairRec>& keyPairList )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_KEY_PAIR WHERE %1 LIKE '%%2%'" ).arg( strTarget ).arg( strWord );

    if( nStatus >= 0 ) strSQL += QString( " AND STATUS = %1" ).arg( nStatus );

    strSQL += QString( " ORDER BY NUM DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getKeyPairList( strSQL, keyPairList );
}

int DBMgr::getKeyPairRec( int nNum, KeyPairRec& keyPairRec )
{
    QList<KeyPairRec> keyPairList;
    QString strQuery = QString( "SELECT * FROM TB_KEY_PAIR WHERE NUM = %1" ).arg(nNum);

    _getKeyPairList( strQuery, keyPairList );
    if( keyPairList.size() <= 0 ) return -1;

    keyPairRec = keyPairList.at(0);

    return 0;
}

int DBMgr::_getKeyPairList( QString strQuery, QList<KeyPairRec>& keyPairList )
{
    int         iCount = 0;
    QSqlQuery   SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosRegTime = SQL.record().indexOf( "REGTIME" );
    int nPosAlg = SQL.record().indexOf( "ALGORITHM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosPublic = SQL.record().indexOf( "PUBLIC" );
    int nPosPrivate = SQL.record().indexOf( "PRIVATE" );
    int nPosParam = SQL.record().indexOf( "PARAM" );
    int nPosStatus = SQL.record().indexOf( "STATUS" );

    while( SQL.next() )
    {
        KeyPairRec keyPairRec;

        keyPairRec.setNum( SQL.value(nPosNum).toInt() );
        keyPairRec.setRegTime( SQL.value(nPosRegTime).toInt());
        keyPairRec.setAlg( SQL.value(nPosAlg).toString() );
        keyPairRec.setName( SQL.value(nPosName).toString() );
        keyPairRec.setPublicKey( SQL.value(nPosPublic).toString() );
        keyPairRec.setPrivateKey( SQL.value(nPosPrivate).toString() );
        keyPairRec.setParam( SQL.value(nPosParam).toString() );
        keyPairRec.setStatus( SQL.value(nPosStatus).toInt() );

        keyPairList.append( keyPairRec );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::getAdminRec( int nSeq, AdminRec& adminRec )
{
    QList<AdminRec> adminList;
    QString strQuery = QString( "SELECT * FROM TB_ADMIN WHERE SEQ = %1" ).arg(nSeq);

    _getAdminList( strQuery, adminList );
    if( adminList.size() <= 0 ) return -1;

    adminRec = adminList.at(0);
    return 0;
}

int DBMgr::getAdminList( QList<AdminRec>& adminList )
{
    QString strSQL;

    strSQL = QString( "SELECT * FROM TB_ADMIN " );
    strSQL += "ORDER BY SEQ DESC";

    return _getAdminList( strSQL, adminList );
}

int DBMgr::getReqRec( int nNum, ReqRec& reqRec )
{
    QList<ReqRec> reqList;
    QString strQuery = QString( "SELECT * FROM TB_REQ WHERE SEQ = %1" ).arg(nNum);

    _getReqList( strQuery, reqList );
    if( reqList.size() <= 0 ) return -1;

    reqRec = reqList.at(0);
    return 0;
}

int DBMgr::getRevokeRec( int nSeq, RevokeRec& revokeRec )
{
    QList<RevokeRec> revokeList;
    QString strQuery = QString( "SELECT * FROM TB_REVOKED WHERE SEQ = %1").arg(nSeq);

    _getRevokeList( strQuery, revokeList );
    if( revokeList.size() <= 0 ) return -1;

    revokeRec = revokeList.at(0);
    return 0;
}

int DBMgr::getRevokeRecByCertNum( int nCertNum, RevokeRec& revokeRec )
{
    QList<RevokeRec> revokeList;
    QString strQuery = QString( "SELECT * FROM TB_REVOKED WHERE CERTNUM = %1").arg(nCertNum);

    _getRevokeList( strQuery, revokeList );
    if( revokeList.size() <= 0 ) return -1;

    revokeRec = revokeList.at(0);
    return 0;
}

int DBMgr::getRevokeList( int nIssuerNum, QList<RevokeRec>& revokeList )
{
    QString strQuery = QString("SELECT * FROM TB_REVOKED WHERE IssuerNum = %1 ORDER BY SEQ DESC").arg(nIssuerNum);

    return _getRevokeList( strQuery, revokeList );
}

int DBMgr::getRevokeList( int nIssuerNum, int nOffset, int nLimit, QList<RevokeRec>& revokeList )
{
    QString strQuery = QString("SELECT * FROM TB_REVOKED WHERE IssuerNum = %1 "
                               "ORDER BY SEQ DESC LIMIT %2 OFFSET %3")
            .arg(nIssuerNum)
            .arg( nLimit )
            .arg( nOffset );

    return _getRevokeList( strQuery, revokeList );
}

int DBMgr::getRevokeList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<RevokeRec>& revokeList )
{
    QString strQuery = QString("SELECT * FROM TB_REVOKED WHERE IssuerNum = %1" ).arg( nIssuerNum );
    strQuery += QString( " AND %1 LIKE '%%2%' ORDER BY SEQ DESC LIMIT %3 OFFSET %4 ")
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getRevokeList( strQuery, revokeList );
}

int DBMgr::getRevokeList( int nIssuerNum, QString strCRLDP, QList<RevokeRec>& revokeList )
{
    QString strQuery = QString( "SELECT * FROM TB_REVOKED WHERE ISSUERNUM = %1 AND CRLDP = '%2'")
            .arg( nIssuerNum )
            .arg( strCRLDP );

    return _getRevokeList( strQuery, revokeList );
}

int DBMgr::getUserRec( int nSeq, UserRec& userRec )
{
    QList<UserRec> userList;
    QString strQuery = QString( "SELECT * FROM TB_USER WHERE NUM = %1").arg(nSeq);

    _getUserList( strQuery, userList );
    if( userList.size() <= 0 ) return -1;

    userRec = userList.at(0);

    return 0;
}

int DBMgr::getKMSRec( int nSeq, KMSRec& kmsRec )
{
    QList<KMSRec> kmsList;
    QString strQuery = QString( "SELECT * FROM TB_KMS WHERE SEQ = %1").arg(nSeq);

    _getKMSList( strQuery, kmsList );
    if( kmsList.size() <= 0 ) return -1;

    kmsRec = kmsList.at(0);

    return 0;
}

int DBMgr::getAuditRec( int nSeq, AuditRec& auditRec )
{
    QList<AuditRec> auditList;
    QString strQuery = QString( "SELECT * FROM TB_AUDIT WHERE SEQ = %1").arg(nSeq);

    _getAuditList( strQuery, auditList );

    if( auditList.size() <= 0 ) return -1;

    auditRec = auditList.at(0);

    return 0;
}

int DBMgr::getUserList( QList<UserRec>& userList )
{
    QString strQuery = QString("SELECT * FROM TB_USER ORDER BY NUM DESC" );

    return _getUserList( strQuery, userList );
}

int DBMgr::getUserList( int nOffset, int nLimit, QList<UserRec>& userList )
{
    QString strQuery = QString("SELECT * FROM TB_USER ORDER BY NUM DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getUserList( strQuery, userList );
}

int DBMgr::getUserList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<UserRec>& userList )
{
    QString strQuery = QString("SELECT * FROM TB_USER WHERE %1 LIKE '%%2%' ORDER BY NUM DESC LIMIT %3 OFFSET %4" )
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getUserList( strQuery, userList );
}

int DBMgr::getKMSList( QList<KMSRec>& kmsList )
{
    QString strQuery = QString("SELECT * FROM TB_KMS ORDER BY SEQ DESC" );

    return _getKMSList( strQuery, kmsList );
}

int DBMgr::getKMSList( int nOffset, int nLimit, QList<KMSRec>& kmsList )
{
    QString strQuery = QString("SELECT * FROM TB_KMS ORDER BY SEQ DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getKMSList( strQuery, kmsList );
}

int DBMgr::getKMSList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<KMSRec>& kmsList )
{
    QString strQuery = QString("SELECT * FROM TB_KMS WHERE %1 LIKE '%%2%' ORDER BY SEQ DESC LIMIT %3 OFFSET %4" )
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getKMSList( strQuery, kmsList );
}

int DBMgr::getKMSAttribList( int nNum, QList<KMSAttribRec>& kmsAttribList )
{
    QString strQuery = QString("SELECT * FROM TB_KMS_ATTRIB WHERE NUM = %1" )
            .arg( nNum );

    return _getKMSAttribList( strQuery, kmsAttribList );
}

int DBMgr::getAuditList( QList<AuditRec>& auditList )
{
    QString strQuery = QString("SELECT * FROM TB_AUDIT ORDER BY SEQ DESC" );

    return _getAuditList( strQuery, auditList );
}

int DBMgr::getAuditList( int nOffset, int nLimit, QList<AuditRec>& auditList )
{
    QString strQuery = QString("SELECT * FROM TB_AUDIT ORDER BY SEQ DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getAuditList( strQuery, auditList );
}

int DBMgr::getAuditList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<AuditRec>& auditList )
{
    QString strQuery = QString("SELECT * FROM TB_AUDIT WHERE %1 LIKE '%%2%' ORDER BY SEQ DESC LIMIT %3 OFFSET %4" )
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getAuditList( strQuery, auditList );
}

int DBMgr::getTSPList( QList<TSPRec>& tspList )
{
    QString strQuery = QString("SELECT * FROM TB_TSP ORDER BY SEQ DESC" );

    return _getTSPList( strQuery, tspList );
}

int DBMgr::getTSPList( int nOffset, int nLimit, QList<TSPRec>& tspList )
{
    QString strQuery = QString("SELECT * FROM TB_TSP ORDER BY SEQ DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getTSPList( strQuery, tspList );
}

int DBMgr::getTSPList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<TSPRec>& tspList )
{
    QString strQuery = QString("SELECT * FROM TB_TSP WHERE %1 LIKE '%%2%' ORDER BY SEQ DESC LIMIT %3 OFFSET %4" )
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getTSPList( strQuery, tspList );
}

int DBMgr::getSignerList( int nType, QList<SignerRec>& signerList )
{
    QString strQuery = QString("SELECT * FROM TB_SIGNER WHERE TYPE = %1 ORDER BY NUM DESC").arg( nType );

    return _getSignerList( strQuery, signerList );
}

int DBMgr::getSignerRec( int nNum, SignerRec& signerRec )
{
    QList<SignerRec> signerList;
    QString strQuery = QString( "SELECT * FROM TB_SIGNER WHERE NUM = %1").arg( nNum );

    _getSignerList( strQuery, signerList );
    if( signerList.size() <= 0 ) return -1;

    signerRec = signerList.at(0);

    return 0;
}

int DBMgr::getTSPRec( int nSeq, TSPRec& tspRec )
{
    QList<TSPRec> tspList;
    QString strQuery = QString( "SELECT * FROM TB_TSP WHERE SEQ = %1").arg( nSeq );

    _getTSPList( strQuery, tspList );
    if( tspList.size() <= 0 ) return -1;

    tspRec = tspList.at(0);

    return 0;
}

int DBMgr::getCRLRec(int nNum, CRLRec &crlRec)
{
    QList<CRLRec> crlList;
    QString strQuery = QString( "SELECT * FROM TB_CRL WHERE NUM = %1").arg(nNum);

    _getCRLList( strQuery, crlList );
    if( crlList.size() <= 0 ) return -1;

    crlRec = crlList.at(0);
    return 0;
}

int DBMgr::getReqList( int nStatus, QList<ReqRec>& reqList )
{
    QString strSQL;

    strSQL = QString( "SELECT * FROM TB_REQ" );
    if( nStatus >= 0 ) strSQL += QString( " WHERE STATUS = %1 " ).arg( nStatus );

    strSQL += "ORDER BY SEQ DESC";

    return _getReqList( strSQL, reqList );
}

int DBMgr::getReqList( int nStatus, int nOffset, int nLimit, QList<ReqRec>& reqList )
{
    QString strQuery;

    strQuery = QString( "SELECT * FROM TB_REQ" );
    if( nStatus >= 0 ) strQuery += QString( " WHERE STATUS = %1" ).arg( nStatus );

    strQuery += QString( " ORDER BY SEQ DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getReqList( strQuery, reqList );
}

int DBMgr::getReqList( int nStatus, QString strTarget, QString strWord, int nOffset, int nLimit, QList<ReqRec>& reqList )
{
    QString strQuery;

    strQuery = QString( "SELECT * FROM TB_REQ WHERE %1 LIKE '%%2%'" ).arg( strTarget ).arg( strWord );
    if( nStatus >= 0 ) strQuery += QString( " AND STATUS = %1" ).arg( nStatus );

    strQuery += QString( " ORDER BY SEQ DESC LIMIT %1 OFFSET %2" ).arg( nLimit ).arg( nOffset );

    return _getReqList( strQuery, reqList );
}

int DBMgr::_getReqList( QString strQuery, QList<ReqRec>& reqList )
{
    int iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosRegTime = SQL.record().indexOf( "REGTIME" );
    int nPosKeyNum = SQL.record().indexOf( "KEY_NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosDN = SQL.record().indexOf( "DN" );
    int nPosCSR = SQL.record().indexOf( "CSR" );
    int nPosHash = SQL.record().indexOf( "HASH" );
    int nPosStatus = SQL.record().indexOf( "Status" );

    while ( SQL.next()) {
        ReqRec reqRec;

        reqRec.setSeq( SQL.value(nPosSeq).toInt() );
        reqRec.setRegTime( SQL.value(nPosRegTime).toInt());
        reqRec.setKeyNum( SQL.value(nPosKeyNum).toInt() );
        reqRec.setName( SQL.value(nPosName).toString() );
        reqRec.setDN( SQL.value(nPosDN).toString() );
        reqRec.setCSR( SQL.value(nPosCSR).toString() );
        reqRec.setHash( SQL.value(nPosHash).toString() );
        reqRec.setStatus( SQL.value(nPosStatus).toInt() );

        reqList.append( reqRec );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::getCRLDPListFromCert( int nIssuerNum, QList<QString>& crldpList )
{
    QString strQuery = QString( "SELECT DISTINCT(CRLDP) FROM TB_CERT WHERE ISSUERNUM = %1").arg( nIssuerNum );

    QSqlQuery SQL(strQuery);

    int nPosCRLDP = SQL.record().indexOf( "CRLDP" );

    while( SQL.next() )
    {
        QString strCRLDP;

        strCRLDP = SQL.value( nPosCRLDP ).toString();

        crldpList.append( strCRLDP );
    }

    SQL.finish();

    return 0;
}

int DBMgr::addKeyPairRec(KeyPairRec& keyPair)
{
    int i = 0;
    QSqlQuery query;

    if( keyPair.getNum() < 0 )
    {
        int nSeq = getNextVal( "TB_KEY_PAIR" );
        if( nSeq < 0 ) return -1;

        keyPair.setNum( nSeq );
    }

    query.prepare( "INSERT INTO TB_KEY_PAIR "
                   "(NUM, REGTIME, ALGORITHM, NAME, PUBLIC, PRIVATE, PARAM, STATUS ) "
                   "VALUES ( ?, ?, ?, ?, ?, ?, ?, ? )" );

    query.bindValue(i++, keyPair.getNum() );
    query.bindValue(i++, keyPair.getRegTime());
    query.bindValue(i++, keyPair.getAlg() );
    query.bindValue(i++, keyPair.getName() );
    query.bindValue(i++, keyPair.getPublicKey() );
    query.bindValue(i++, keyPair.getPrivateKey() );
    query.bindValue(i++, keyPair.getParam() );
    query.bindValue(i++, keyPair.getStatus() );

    if( query.exec() == false )
    {
        query.finish();
//        qDebug() << query.lastError();
        return -2;
    }

    query.finish();
    return 0;
}

int DBMgr::addReqRec( ReqRec& reqRec )
{
    int i = 0;
    QSqlQuery query;

    if( reqRec.getSeq() < 0 )
    {
        int nSeq = getNextVal( "TB_REQ" );
        if( nSeq < 0 ) return -1;

        reqRec.setSeq( nSeq );
    }

    query.prepare( "INSERT INTO TB_REQ "
                   "(SEQ, REGTIME, KEY_NUM, NAME, DN, CSR, HASH, STATUS ) "
                   "VALUES( ?, ?, ?, ?, ?, ?, ?, ? )" );

    query.bindValue( i++, reqRec.getSeq() );
    query.bindValue( i++, reqRec.getRegTime() );
    query.bindValue( i++, reqRec.getKeyNum() );
    query.bindValue( i++, reqRec.getName() );
    query.bindValue( i++, reqRec.getDN() );
    query.bindValue( i++, reqRec.getCSR() );
    query.bindValue( i++, reqRec.getHash() );
    query.bindValue( i++, reqRec.getStatus() );

    if( query.exec() == false )
    {
        query.finish();
//        qDebug() << query.lastError().text();
        return  -2;
    }

    query.finish();
    return 0;
}

int DBMgr::getCertProfileList( QList<CertProfileRec>& certProfileList )
{
    QString strSQL = "SELECT * FROM TB_CERT_PROFILE ORDER BY NUM DESC";

    return _getCertProfileList( strSQL, certProfileList );
}

int DBMgr::getCertProfileListByType( int nType, QList<CertProfileRec>& certProfileList )
{
    QString strSQL;
    strSQL = QString( "SELECT * FROM TB_CERT_PROFILE WHERE TYPE = %1 ORDER BY NUM DESC" ).arg( nType );

    return _getCertProfileList( strSQL, certProfileList );
}


int DBMgr::getCertProfileRec( int nNum, CertProfileRec& certProfile )
{
    QString strSQL;
    strSQL = QString( "SELECT * FROM TB_CERT_PROFILE WHERE NUM = %1").arg( nNum );

    QList<CertProfileRec> certProfileList;

    _getCertProfileList( strSQL, certProfileList );
    if( certProfileList.size() <= 0 ) return -1;

    certProfile = certProfileList.at(0);

    return 0;
}

int DBMgr::getCRLProfileRec( int nNum, CRLProfileRec& crlProfile )
{
    QString strSQL;
    strSQL = QString( "SELECT * FROM TB_CRL_PROFILE WHERE NUM = %1" ).arg( nNum );

    QList<CRLProfileRec> crlProfileList;

    _getCRLProfileList( strSQL, crlProfileList );
    if( crlProfileList.size() <= 0 ) return -1;

    crlProfile = crlProfileList.at(0);

    return 0;
}

int DBMgr::_getCertProfileList( QString strQuery, QList<CertProfileRec>& certProfileList )
{
    int iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosType = SQL.record().indexOf( "TYPE" );
    int nPosVersion = SQL.record().indexOf( "VERSION" );
    int nPosNotBefore = SQL.record().indexOf( "NotBefore" );
    int nPosNotAfter = SQL.record().indexOf( "NotAfter" );
    int nPosExtUsage = SQL.record().indexOf( "ExtUsage" );
    int nPosHash = SQL.record().indexOf( "HASH" );
    int nPosDNTemplate = SQL.record().indexOf( "DNTemplate" );

    while( SQL.next() )
    {
        CertProfileRec certProfile;

        certProfile.setNum( SQL.value(nPosNum).toInt() );
        certProfile.setName( SQL.value(nPosName).toString() );
        certProfile.setType( SQL.value(nPosType).toInt());
        certProfile.setVersion( SQL.value(nPosVersion).toInt() );
        certProfile.setNotBefore( SQL.value(nPosNotBefore).toInt() );
        certProfile.setNotAfter( SQL.value(nPosNotAfter).toInt() );
        certProfile.setExtUsage( SQL.value( nPosExtUsage ).toInt());
        certProfile.setHash( SQL.value(nPosHash).toString() );
        certProfile.setDNTemplate( SQL.value(nPosDNTemplate).toString() );

        certProfileList.append( certProfile );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::getCRLList( int nIssuerNum, QList<CRLRec>& crlList )
{
    QString strSQL = QString( "SELECT * FROM TB_CRL WHERE ISSUERNUM = %1 ORDER BY NUM DESC" ).arg( nIssuerNum );

    return _getCRLList( strSQL, crlList );
}

int DBMgr::getCRLList( int nIssuerNum, int nOffset, int nLimit, QList<CRLRec>& crlList )
{
    QString strSQL = QString( "SELECT * FROM TB_CRL WHERE ISSUERNUM = %1 ORDER BY NUM DESC LIMIT %2 OFFSET %3" )
            .arg( nIssuerNum )
            .arg( nLimit )
            .arg( nOffset );

    return _getCRLList( strSQL, crlList );
}

int DBMgr::getCRLList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<CRLRec>& crlList )
{
    QString strSQL = QString( "SELECT * FROM TB_CRL WHERE ISSUERNUM = %1 AND %2 LIKE '%%3%' "
                              "ORDER BY NUM DESC LIMIT %4 OFFSET %5" )
            .arg( nIssuerNum )
            .arg( strTarget )
            .arg( strWord )
            .arg( nLimit )
            .arg( nOffset );

    return _getCRLList( strSQL, crlList );
}

int DBMgr::_getCRLList( QString strQuery, QList<CRLRec>& crlList )
{
    int iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosRegTime = SQL.record().indexOf( "RegTime" );
    int nPosIssuerNum = SQL.record().indexOf( "IssuerNum" );
    int nPosSignAlg = SQL.record().indexOf( "SignAlg" );
    int nPosCRLDP = SQL.record().indexOf( "CRLDP" );
    int nPosCRL = SQL.record().indexOf( "CRL" );

    while( SQL.next() )
    {
        CRLRec crlRec;

        crlRec.setNum( SQL.value(nPosNum).toInt() );
        crlRec.setRegTime( SQL.value(nPosRegTime).toInt());
        crlRec.setIssuerNum( SQL.value(nPosIssuerNum).toInt() );
        crlRec.setSignAlg( SQL.value(nPosSignAlg).toString() );
        crlRec.setCRLDP( SQL.value(nPosCRLDP).toString());
        crlRec.setCRL( SQL.value(nPosCRL).toString() );

        crlList.append( crlRec );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::getCRLProfileList(QList<CRLProfileRec>& crlProfileList)
{
    QString strSQL = "SELECT * FROM TB_CRL_PROFILE ORDER BY NUM DESC";

    return _getCRLProfileList( strSQL, crlProfileList );
}

int DBMgr::_getCRLProfileList( QString strQuery, QList<CRLProfileRec>& crlProfileList )
{
    int iCount = 0;
    QSqlQuery SQL(strQuery);

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosVersion = SQL.record().indexOf( "VERSION" );
    int nPosThisUpdate = SQL.record().indexOf( "THISUPDATE" );
    int nPosNextUpdate = SQL.record().indexOf( "NEXTUPDATE" );
    int nPosHash = SQL.record().indexOf( "HASH" );

    while( SQL.next() )
    {
        CRLProfileRec crlProfile;

        crlProfile.setNum( SQL.value(nPosNum).toInt() );
        crlProfile.setName( SQL.value(nPosName).toString() );
        crlProfile.setVersion( SQL.value(nPosVersion).toInt() );
        crlProfile.setThisUpdate( SQL.value(nPosThisUpdate).toInt() );
        crlProfile.setNextUpdate( SQL.value(nPosNextUpdate).toInt() );
        crlProfile.setHash( SQL.value(nPosHash).toString() );

        crlProfileList.append( crlProfile );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getRevokeList( QString strQuery, QList<RevokeRec>& revokeList )
{
    int iCount = 0;
    QSqlQuery SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosCertNum = SQL.record().indexOf( "CERTNUM" );
    int nPosIssuerNum = SQL.record().indexOf( "ISSUERNUM" );
    int nPosSerial = SQL.record().indexOf( "SERIAL" );
    int nPosRevokeDate = SQL.record().indexOf( "REVOKEDDATE" );
    int nPosReason = SQL.record().indexOf( "REASON" );
    int nPosCRLDP = SQL.record().indexOf( "CRLDP" );

    while( SQL.next() )
    {
        RevokeRec revokeRec;

        revokeRec.setSeq( SQL.value(nPosSeq).toInt() );
        revokeRec.setCertNum( SQL.value(nPosCertNum).toInt() );
        revokeRec.setIssuerNum( SQL.value(nPosIssuerNum).toInt() );
        revokeRec.setSerial( SQL.value(nPosSerial).toString() );
        revokeRec.setRevokeDate( SQL.value(nPosRevokeDate).toInt() );
        revokeRec.setReason( SQL.value(nPosReason).toInt() );
        revokeRec.setCRLDP( SQL.value(nPosCRLDP).toString() );

        revokeList.append( revokeRec );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::getCertProfileExtensionList( int nProfileNum, QList<ProfileExtRec>& profileExtList )
{
    QString strQuery = QString( "SELECT * FROM TB_CERT_PROFILE_EXTENSION WHERE PROFILENUM = %1").arg( nProfileNum );

    return _getProfileExtensionList( strQuery, profileExtList );
}

int DBMgr::getCRLProfileExtensionList( int nProfileNum, QList<ProfileExtRec>& profileExtList )
{
    QString strQuery = QString( "SELECT * FROM TB_CRL_PROFILE_EXTENSION WHERE PROFILENUM = %1").arg( nProfileNum );

    return _getProfileExtensionList( strQuery, profileExtList );
}

int DBMgr::_getProfileExtensionList( QString strQuery, QList<ProfileExtRec>& profileExtensionList )
{
    int iCount = 0;
    QSqlQuery SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosProfileNum = SQL.record().indexOf( "PROFILENUM" );
    int nPosCritical = SQL.record().indexOf( "CRITICAL" );
    int nPosSN = SQL.record().indexOf( "SN" );
    int nPosValue = SQL.record().indexOf( "VALUE" );

    while( SQL.next() )
    {
        ProfileExtRec profileExtension;

        profileExtension.setSeq( SQL.value(nPosSeq).toInt() );
        profileExtension.setProfileNum( SQL.value(nPosProfileNum).toInt() );
        profileExtension.setCritical( SQL.value(nPosCritical).toBool() );
        profileExtension.setSN( SQL.value(nPosSN).toString() );
        profileExtension.setValue( SQL.value(nPosValue).toString() );

        profileExtensionList.append( profileExtension );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getUserList( QString strQuery, QList<UserRec>& userList )
{
    QSqlQuery   SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosRegTime = SQL.record().indexOf( "RegTime" );
    int nPosName = SQL.record().indexOf( "Name" );
    int nPosSSN = SQL.record().indexOf( "SSN" );
    int nPosEmail = SQL.record().indexOf( "Email" );
    int nPosStatus = SQL.record().indexOf( "Status" );
    int nPosRefNum = SQL.record().indexOf( "RefNum" );
    int nPosAuthCode = SQL.record().indexOf( "AuthCode" );

    while( SQL.next() )
    {
        UserRec     user;

        user.setNum( SQL.value(nPosNum).toInt() );
        user.setRegTime( SQL.value(nPosRegTime).toInt());
        user.setName( SQL.value(nPosName).toString() );
        user.setSSN( SQL.value(nPosSSN).toString() );
        user.setEmail( SQL.value(nPosEmail).toString());
        user.setStatus( SQL.value(nPosStatus).toInt());
        user.setRefNum( SQL.value(nPosRefNum).toString());
        user.setAuthCode( SQL.value(nPosAuthCode).toString());

        userList.append( user );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getSignerList( QString strQuery, QList<SignerRec>& signerList )
{
    int         iCount = 0;
    QSqlQuery   SQL(strQuery);

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosRegTime = SQL.record().indexOf( "RegTime");
    int nPosType = SQL.record().indexOf( "TYPE" );
    int nPosDN = SQL.record().indexOf( "DN" );
    int nPosDNHash = SQL.record().indexOf( "DNHash" );
    int nPosStatus = SQL.record().indexOf( "STATUS" );
    int nPosCert = SQL.record().indexOf( "CERT" );
    int nPosInfo = SQL.record().indexOf( "Info" );

    while( SQL.next() )
    {
        SignerRec signer;

        signer.setNum( SQL.value(nPosNum).toInt());
        signer.setRegTime( SQL.value(nPosRegTime).toInt());
        signer.setType( SQL.value(nPosType).toInt());
        signer.setDN( SQL.value(nPosDN).toString());
        signer.setDNHash( SQL.value(nPosDNHash).toString());
        signer.setStatus( SQL.value(nPosStatus).toInt());
        signer.setCert( SQL.value(nPosCert).toString());
        signer.setInfo( SQL.value(nPosInfo).toString());

        signerList.append( signer );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getKMSList( QString strQuery, QList<KMSRec>& kmsList )
{
    int         iCount = 0;
    QSqlQuery   SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosRegTime = SQL.record().indexOf( "RegTime");
    int nPosState = SQL.record().indexOf( "STATE" );
    int nPosType = SQL.record().indexOf( "TYPE" );
    int nPosAlgorithm = SQL.record().indexOf( "ALGORITHM" );
    int nPosID = SQL.record().indexOf( "ID" );
    int nPosInfo = SQL.record().indexOf( "INFO" );

    while( SQL.next() )
    {
        KMSRec kms;

        kms.setSeq( SQL.value(nPosSeq).toInt());
        kms.setRegTime( SQL.value(nPosRegTime).toInt());
        kms.setState( SQL.value(nPosState).toInt());
        kms.setType( SQL.value(nPosType).toInt());
        kms.setAlgorithm( SQL.value(nPosAlgorithm).toInt());
        kms.setID( SQL.value(nPosID).toString());
        kms.setInfo( SQL.value(nPosInfo).toString());

        kmsList.append( kms );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getKMSAttribList( QString strQuery, QList<KMSAttribRec>& kmsAttribList )
{
    int         iCount = 0;
    QSqlQuery   SQL(strQuery);

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosType = SQL.record().indexOf( "TYPE" );
    int nPosValue = SQL.record().indexOf( "VALUE" );

    while( SQL.next() )
    {
        KMSAttribRec kmsAttrib;

        kmsAttrib.setNum( SQL.value(nPosNum).toInt());
        kmsAttrib.setType( SQL.value(nPosType).toInt());
        kmsAttrib.setValue( SQL.value(nPosValue).toString());

        kmsAttribList.append( kmsAttrib );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getAuditList( QString strQuery, QList<AuditRec>& auditList )
{
    int         iCount = 0;
    QSqlQuery   SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosRegTime = SQL.record().indexOf( "RegTime");
    int nPosKind = SQL.record().indexOf( "KIND" );
    int nPosOperation = SQL.record().indexOf( "OPERATION" );
    int nPosUserName = SQL.record().indexOf( "USERNAME" );
    int nPosInfo = SQL.record().indexOf( "INFO" );
    int nPosMAC = SQL.record().indexOf( "MAC" );

    while( SQL.next() )
    {
        AuditRec audit;

        audit.setSeq( SQL.value(nPosSeq).toInt());
        audit.setRegTime( SQL.value(nPosRegTime).toInt());
        audit.setKind( SQL.value(nPosKind).toInt());
        audit.setOperation( SQL.value(nPosOperation).toInt());
        audit.setUserName( SQL.value(nPosUserName).toString());
        audit.setInfo( SQL.value(nPosInfo).toString());
        audit.setMAC( SQL.value(nPosMAC).toString());

        auditList.append( audit );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getTSPList( QString strQuery, QList<TSPRec>& tspList )
{
    QSqlQuery   SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosRegTime = SQL.record().indexOf( "RegTime");
    int nPosSerial = SQL.record().indexOf( "Serial" );
    int nPosSrcHash = SQL.record().indexOf( "SrcHash" );
    int nPosPolicy = SQL.record().indexOf( "Policy" );
    int nPosTSTInfo = SQL.record().indexOf( "TSTInfo" );
    int nPosData = SQL.record().indexOf( "Data" );

    while( SQL.next() )
    {
        TSPRec tsp;

        tsp.setSeq( SQL.value(nPosSeq).toInt());
        tsp.setRegTime( SQL.value(nPosRegTime).toInt());
        tsp.setSerial( SQL.value(nPosSerial).toInt());
        tsp.setSrcHash( SQL.value(nPosSrcHash).toString());
        tsp.setPolicy( SQL.value(nPosPolicy).toString());
        tsp.setTSTInfo( SQL.value(nPosTSTInfo).toString());
        tsp.setData( SQL.value(nPosData).toString());

        tspList.append( tsp );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getAdminList( QString strQuery, QList<AdminRec>& adminList )
{
    QSqlQuery   SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosStatus = SQL.record().indexOf( "Status");
    int nPosType = SQL.record().indexOf( "Type" );
    int nPosName = SQL.record().indexOf( "Name" );
    int nPosPassword = SQL.record().indexOf( "Password" );
    int nPosEmail = SQL.record().indexOf( "Email" );

    while( SQL.next() )
    {
        AdminRec admin;

        admin.setSeq( SQL.value(nPosSeq).toInt());
        admin.setStatus( SQL.value(nPosStatus).toInt());
        admin.setType( SQL.value(nPosType).toInt());
        admin.setName( SQL.value(nPosName).toString());
        admin.setPassword( SQL.value(nPosPassword).toString());
        admin.setEmail( SQL.value(nPosEmail).toString());

        adminList.append( admin );
    }

    SQL.finish();
    return 0;
}

int DBMgr::_getConfigList( QString strQuery, QList<ConfigRec>& configList )
{
    QSqlQuery   SQL(strQuery);

    int nPosNum = SQL.record().indexOf( "Num" );
    int nPosKind = SQL.record().indexOf( "Kind");
    int nPosName = SQL.record().indexOf( "Name" );
    int nPosValue = SQL.record().indexOf( "Value" );

    while( SQL.next() )
    {
        ConfigRec config;
        config.setNum( SQL.value(nPosNum).toInt());
        config.setKind( SQL.value(nPosKind).toInt());
        config.setName( SQL.value(nPosName).toString());
        config.setValue( SQL.value( nPosValue).toString());

        configList.append( config );
    }

    SQL.finish();
    return 0;
}

/*
int DBMgr::getSeq( QString strTable )
{
    int nSeq = -1;

    QString strSQL;
    strSQL.sprintf( "SELECT SEQ FROM SQLITE_SEQUENCE WHERE NAME = '%s'", strTable.toStdString().c_str() );
    QSqlQuery query( strSQL );

    int nPosSeq = query.record().indexOf( "SEQ" );

    while( query.next() )
    {
        nSeq = query.value(nPosSeq).toInt();
        break;
    }

    query.finish();
    return nSeq;
}
*/

int DBMgr::getNextVal( const QString strTable )
{
    int nSeq = -1;

    QSqlQuery sqlQuery;
    QSqlQuery subQuery;
    subQuery.prepare( "UPDATE TB_SEQ SET SEQ=SEQ+1 WHERE NAME = ?");
    subQuery.bindValue( 0, strTable );

    if( subQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError().text();
        subQuery.finish();
        return -1;
    }

    sqlQuery.prepare( "SELECT SEQ FROM TB_SEQ WHERE NAME = ?" );
    sqlQuery.bindValue( 0, strTable );
    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError().text();
        sqlQuery.finish();
        return -1;
    }

    sqlQuery.finish();
    nSeq = getLastVal( strTable );

    return nSeq;
}

int DBMgr::getLastVal( const QString strTable )
{
    int nSeq = -1;
    int nPosSeq = 0;

    QSqlQuery sqlQuery;

    sqlQuery.prepare( "SELECT SEQ FROM TB_SEQ WHERE NAME = ?");
    sqlQuery.bindValue( 0, strTable );
    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError().text();
        sqlQuery.finish();
        return -1;
    }

    nPosSeq = sqlQuery.record().indexOf( "SEQ" );

    if( sqlQuery.next() )
    {
        nSeq = sqlQuery.value(nPosSeq).toInt();
        sqlQuery.finish();
    }
    else
    {
        QSqlQuery inQuery;
        inQuery.prepare( "INSERT INTO TB_SEQ ( SEQ, NAME ) VALUES( 100, ? )");
        inQuery.bindValue( 0, strTable );
        if( inQuery.exec() == false )
        {
            inQuery.finish();
//            qDebug() << inQuery.lastError().text();
            return -1;
        }

        inQuery.finish();
        nSeq = 100;
    }

    return nSeq;
}

int DBMgr::addCertRec( CertRec& certRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( certRec.getNum() < 0 )
    {
        int nSeq = getNextVal( "TB_CERT" );
        if( nSeq < 0 ) return -1;

        certRec.setNum( nSeq );
    }


    sqlQuery.prepare( "INSERT INTO TB_CERT "
                      "( NUM, REGTIME, KEYNUM, USERNUM, SIGNALG, CERT, ISSELF, ISCA, ISSUERNUM, SUBJECTDN, STATUS, SERIAL, DNHASH, KEYHASH, CRLDP ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, certRec.getNum() );
    sqlQuery.bindValue( i++, certRec.getRegTime() );
    sqlQuery.bindValue( i++, certRec.getKeyNum() );
    sqlQuery.bindValue( i++, certRec.getUserNum() );
    sqlQuery.bindValue( i++, certRec.getSignAlg() );
    sqlQuery.bindValue( i++, certRec.getCert() );
    sqlQuery.bindValue( i++, certRec.isSelf() );
    sqlQuery.bindValue( i++, certRec.isCA() );
    sqlQuery.bindValue( i++, certRec.getIssuerNum() );
    sqlQuery.bindValue( i++, certRec.getSubjectDN() );
    sqlQuery.bindValue( i++, certRec.getStatus() );
    sqlQuery.bindValue( i++, certRec.getSerial() );
    sqlQuery.bindValue( i++, certRec.getDNHash() );
    sqlQuery.bindValue( i++, certRec.getKeyHash() );
    sqlQuery.bindValue( i++, certRec.getCRLDP() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::modKeyPairStatus( int nNum, int nStatus )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_KEY_PAIR SET STATUS = ? WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, nStatus );
    sqlQuery.bindValue( 1, nNum );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::modKeyPairPrivate( int nNum, const QString strPrivate )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_KEY_PAIR SET PRIVATE = ? WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, strPrivate );
    sqlQuery.bindValue( 1, nNum );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::modReqStatus( int nSeq, int nStatus )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_REQ SET STATUS = ? WHERE SEQ = ?;" );

    sqlQuery.bindValue( 0, nStatus );
    sqlQuery.bindValue( 1, nSeq );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::modCertStatus( int nNum, int nStatus )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CERT SET STATUS = ? WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, nStatus );
    sqlQuery.bindValue( 1, nNum );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::modCertProfileRec( int nProfileNum, CertProfileRec profileRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CERT_PROFILE SET "
                      "NAME = ?, "
                      "TYPE = ?, "
                      "VERSION = ?, "
                      "NOTBEFORE = ?, "
                      "NOTAFTER = ?, "
                      "EXTUSAGE = ?, "
                      "HASH = ?, "
                      "DNTemplate = ? "
                      "WHERE NUM = ?;" );

    sqlQuery.bindValue( i++, profileRec.getName() );
    sqlQuery.bindValue( i++, profileRec.getType() );
    sqlQuery.bindValue( i++, profileRec.getVersion() );
    sqlQuery.bindValue( i++, (int)profileRec.getNotBefore() );
    sqlQuery.bindValue( i++, (int)profileRec.getNotAfter() );
    sqlQuery.bindValue( i++, profileRec.getExtUsage() );
    sqlQuery.bindValue( i++, profileRec.getHash() );
    sqlQuery.bindValue( i++, profileRec.getDNTemplate() );
    sqlQuery.bindValue( i++, nProfileNum );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::modCRLProfileRec( int nProfileNum, CRLProfileRec profileRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CRL_PROFILE SET "
                      "NAME = ?, "
                      "VERSION = ?, "
                      "THISUPDATE = ?, "
                      "NEXTUPDATE = ?, "
                      "HASH = ? "
                      "WHERE NUM = ?;" );

    sqlQuery.bindValue( i++, profileRec.getName() );
    sqlQuery.bindValue( i++, profileRec.getVersion() );
    sqlQuery.bindValue( i++, (int)profileRec.getThisUpdate() );
    sqlQuery.bindValue( i++, (int)profileRec.getNextUpdate() );
    sqlQuery.bindValue( i++, profileRec.getHash() );
    sqlQuery.bindValue( i++, nProfileNum );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::modAdminRec( int nSeq, AdminRec adminRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_ADMIN SET "
                      "STATUS = ?, "
                      "TYPE = ?, "
                      "NAME = ?, "
                      "PASSWORD = ?, "
                      "EMAIL = ? "
                      "WHERE SEQ = ?;" );

    sqlQuery.bindValue( i++, adminRec.getStatus() );
    sqlQuery.bindValue( i++, adminRec.getType() );
    sqlQuery.bindValue( i++, adminRec.getName() );
    sqlQuery.bindValue( i++, adminRec.getPassword() );
    sqlQuery.bindValue( i++, adminRec.getEmail() );
    sqlQuery.bindValue( i++, nSeq );

    if( sqlQuery.exec() == false )
    {
        sqlQuery.finish();
//        qDebug() << sqlQuery.lastError();
        return -1;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::addCRLRec( CRLRec& crlRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( crlRec.getNum() < 0 )
    {
        int nSeq = getNextVal( "TB_CRL" );
        if( nSeq < 0 ) return -1;
        crlRec.setNum( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_CRL "
                      "( NUM, REGTIME, ISSUERNUM, SIGNALG, CRLDP, CRL ) "
                      "VALUES( ?,?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, crlRec.getNum() );
    sqlQuery.bindValue( i++, crlRec.getRegTime() );
    sqlQuery.bindValue( i++, crlRec.getIssuerNum() );
    sqlQuery.bindValue( i++, crlRec.getSignAlg() );
    sqlQuery.bindValue( i++, crlRec.getCRLDP() );
    sqlQuery.bindValue( i++, crlRec.getCRL() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::addCertProfileRec( CertProfileRec& certProfileRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CERT_PROFILE "
                      "( NUM, NAME, TYPE, VERSION, NOTBEFORE, NOTAFTER, EXTUSAGE, HASH, DNTEMPLATE ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, certProfileRec.getNum() );
    sqlQuery.bindValue( i++, certProfileRec.getName() );
    sqlQuery.bindValue( i++, certProfileRec.getType() );
    sqlQuery.bindValue( i++, certProfileRec.getVersion() );
    sqlQuery.bindValue( i++, QString( "%1" ).arg( certProfileRec.getNotBefore() ) );
    sqlQuery.bindValue( i++, QString( "%1").arg( certProfileRec.getNotAfter() ) );
    sqlQuery.bindValue( i++, certProfileRec.getExtUsage() );
    sqlQuery.bindValue( i++, certProfileRec.getHash() );
    sqlQuery.bindValue( i++, certProfileRec.getDNTemplate() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addCRLProfileRec( CRLProfileRec& crlProfileRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    sqlQuery.prepare( "INSERT INTO TB_CRL_PROFILE "
                      "( NUM, NAME, VERSION, THISUPDATE, NEXTUPDATE, HASH ) "
                      "VALUES( ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, crlProfileRec.getNum() );
    sqlQuery.bindValue( i++, crlProfileRec.getName() );
    sqlQuery.bindValue( i++, crlProfileRec.getVersion() );
    sqlQuery.bindValue( i++, QString("%1").arg(crlProfileRec.getThisUpdate()));
    sqlQuery.bindValue( i++, QString("%1").arg(crlProfileRec.getNextUpdate()));
    sqlQuery.bindValue( i++, crlProfileRec.getHash());

    sqlQuery.exec();
    return 0;
}

int DBMgr::getCertProfileNextNum()
{
    int nNextNum = -1;

    QString strSQL;
    strSQL = QString( "SELECT MAX(num)+1 FROM TB_CERT_PROFILE" );
    QSqlQuery query( strSQL );

    while( query.next() )
    {
        nNextNum = query.value(0).toInt();
        break;
    }

    query.finish();
    return nNextNum;
}

int DBMgr::getCRLProfileNextNum()
{
    int nNextNum = -1;

    QString strSQL;
    strSQL = QString( "SELECT MAX(num)+1 FROM TB_CRL_PROFILE" );
    QSqlQuery query( strSQL );

    while( query.next() )
    {
        nNextNum = query.value(0).toInt();
        break;
    }

    query.finish();
    return nNextNum;
}

int DBMgr::addCertProfileExtension( ProfileExtRec& profileExtension )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( profileExtension.getSeq() < 0 )
    {
        int nSeq = getNextVal( "TB_CERT_PROFILE_EXTENSION" );
        if( nSeq < 0 ) return -1;

        profileExtension.setSeq( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_CERT_PROFILE_EXTENSION "
                      "( SEQ, PROFILENUM, CRITICAL, SN, VALUE ) "
                      "VALUES( ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, profileExtension.getSeq() );
    sqlQuery.bindValue( i++, profileExtension.getProfileNum() );
    sqlQuery.bindValue( i++, profileExtension.isCritical() );
    sqlQuery.bindValue( i++, profileExtension.getSN() );
    sqlQuery.bindValue( i++, profileExtension.getValue() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::addCRLProfileExtension( ProfileExtRec& profileExtension )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( profileExtension.getSeq() < 0 )
    {
        int nSeq = getNextVal( "TB_CRL_PROFILE_EXTENSION" );
        if( nSeq < 0 ) return -1;

        profileExtension.setSeq( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_CRL_PROFILE_EXTENSION "
                      "( SEQ, PROFILENUM, CRITICAL, SN, VALUE ) "
                      "VALUES( ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, profileExtension.getSeq() );
    sqlQuery.bindValue( i++, profileExtension.getProfileNum() );
    sqlQuery.bindValue( i++, profileExtension.isCritical() );
    sqlQuery.bindValue( i++, profileExtension.getSN() );
    sqlQuery.bindValue( i++, profileExtension.getValue() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}


int DBMgr::addRevokeRec( RevokeRec& revokeRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( revokeRec.getSeq() < 0 )
    {
        int nSeq = getNextVal( "TB_REVOKED" );
        if( nSeq < 0 ) return -1;

        revokeRec.setSeq( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_REVOKED "
                      "( SEQ, CERTNUM, ISSUERNUM, SERIAL, REVOKEDDATE, REASON, CRLDP ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, revokeRec.getSeq() );
    sqlQuery.bindValue( i++, revokeRec.getCertNum() );
    sqlQuery.bindValue( i++, revokeRec.getIssuerNum() );
    sqlQuery.bindValue( i++, revokeRec.getSerial() );
    sqlQuery.bindValue( i++, revokeRec.getRevokeDate() );
    sqlQuery.bindValue( i++, revokeRec.getReason() );
    sqlQuery.bindValue( i++, revokeRec.getCRLDP() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::addUserRec(UserRec &userRec)
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( userRec.getNum() < 0 )
    {
        int nSeq = getNextVal( "TB_USER" );
        if( nSeq < 0 ) return -1;

        userRec.setNum( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_USER "
                      "( NUM, REGTIME, NAME, SSN, EMAIL, STATUS, REFNUM, AUTHCODE ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, userRec.getNum() );
    sqlQuery.bindValue( i++, userRec.getRegTime() );
    sqlQuery.bindValue( i++, userRec.getName() );
    sqlQuery.bindValue( i++, userRec.getSSN() );
    sqlQuery.bindValue( i++, userRec.getEmail() );
    sqlQuery.bindValue( i++, userRec.getStatus() );
    sqlQuery.bindValue( i++, userRec.getRefNum() );
    sqlQuery.bindValue( i++, userRec.getAuthCode() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::addSignerRec( SignerRec& signerRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( signerRec.getNum() < 0 )
    {
        int nSeq = getNextVal( "TB_SIGNER" );
        if( nSeq < 0 ) return -1;

        signerRec.setNum( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_SIGNER "
                      "( NUM, REGTIME, TYPE, DN, DNHASH, STATUS, CERT, INFO ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, signerRec.getNum() );
    sqlQuery.bindValue( i++, signerRec.getRegTime() );
    sqlQuery.bindValue( i++, signerRec.getType() );
    sqlQuery.bindValue( i++, signerRec.getDN() );
    sqlQuery.bindValue( i++, signerRec.getDNHash() );
    sqlQuery.bindValue( i++, signerRec.getStatus() );
    sqlQuery.bindValue( i++, signerRec.getCert() );
    sqlQuery.bindValue( i++, signerRec.getInfo() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::addKMSRec( KMSRec& kmsRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( kmsRec.getSeq() < 0 )
    {
        int nSeq = getNextVal("TB_KMS");
        if( nSeq < 0 ) return -1;

        kmsRec.setSeq( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_KMS "
                      "( SEQ, REGTIME, STATE, TYPE, ALGORITHM, ID, INFO ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, kmsRec.getSeq() );
    sqlQuery.bindValue( i++, kmsRec.getRegTime() );
    sqlQuery.bindValue( i++, kmsRec.getState() );
    sqlQuery.bindValue( i++, kmsRec.getType() );
    sqlQuery.bindValue( i++, kmsRec.getAlgorithm());
    sqlQuery.bindValue( i++, kmsRec.getID() );
    sqlQuery.bindValue( i++, kmsRec.getInfo() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::addAuditRec( AuditRec& auditRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( auditRec.getSeq() < 0 )
    {
        int nSeq = getNextVal( "TB_AUDIT" );
        if( nSeq < 0 ) return -1;

        auditRec.setSeq( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_AUDIT "
                      "( SEQ, REGTIME, KIND, OPERATION, USERNAME, INFO, MAC ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, auditRec.getSeq() );
    sqlQuery.bindValue( i++, auditRec.getRegTime() );
    sqlQuery.bindValue( i++, auditRec.getKind() );
    sqlQuery.bindValue( i++, auditRec.getOperation() );
    sqlQuery.bindValue( i++, auditRec.getUserName() );
    sqlQuery.bindValue( i++, auditRec.getInfo() );
    sqlQuery.bindValue( i++, auditRec.getMAC() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();

    return 0;
}

int DBMgr::addAdminRec( AdminRec& adminRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( adminRec.getSeq() < 0 )
    {
        int nSeq = getNextVal( "TB_ADMIN" );
        if( nSeq < 0 ) return -1;

        adminRec.setSeq( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_ADMIN "
                      "( SEQ, STATUS, TYPE, NAME, PASSWORD, EMAIL ) "
                      "VALUES( ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, adminRec.getSeq() );
    sqlQuery.bindValue( i++, adminRec.getStatus() );
    sqlQuery.bindValue( i++, adminRec.getType() );
    sqlQuery.bindValue( i++, adminRec.getName() );
    sqlQuery.bindValue( i++, adminRec.getPassword() );
    sqlQuery.bindValue( i++, adminRec.getEmail() );

    if( sqlQuery.exec() == false )
    {
//        qDebug() << sqlQuery.lastError();
        sqlQuery.finish();
        return -2;
    }

    sqlQuery.finish();
    return 0;
}

int DBMgr::delCertProfile( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CERT_PROFILE WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::delCRLProfile( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CRL_PROFILE WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delCertProfileExtensionList( int nProfileNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CERT_PROFILE_EXTENSION WHERE PROFILENUM = ?");

    sqlQuery.bindValue( 0, nProfileNum );

    sqlQuery.exec();
}

int DBMgr::delCertProfileExtension( int nProfileNum, const QString strSN )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CERT_PROFILE_EXTENSION WHERE PROFILENUM = ? AND SN = ?");

    sqlQuery.bindValue( 0, nProfileNum );
    sqlQuery.bindValue( 1, strSN );

    sqlQuery.exec();
}

int DBMgr::delCRLProfileExtensionList( int nProfileNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CRL_PROFILE_EXTENSION WHERE PROFILENUM = ?");

    sqlQuery.bindValue( 0, nProfileNum );

    sqlQuery.exec();
}

int DBMgr::delCRLProfileExtension( int nProfileNum, const QString strSN )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CRL_PROFILE_EXTENSION WHERE PROFILENUM = ? AND SN = ?");

    sqlQuery.bindValue( 0, nProfileNum );
    sqlQuery.bindValue( 1, strSN );

    sqlQuery.exec();
}


int DBMgr::delCertRec( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CERT WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delCRLRec( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CRL WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delKeyPairRec(int nNum)
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_KEY_PAIR WHERE NUM = ?" );
    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delReqRec(int nNum)
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_REQ WHERE SEQ = ?" );
    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delUserRec(int nNum)
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_USER WHERE NUM = ?" );
    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delSignerRec(int nNum)
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_SIGNER WHERE NUM = ?" );
    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delKMSRec( int nSeq )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_KMS WHERE SEQ = ?" );
    sqlQuery.bindValue( 0, nSeq );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delAdminRec( int nSeq )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_ADMIN WHERE SEQ = ?" );
    sqlQuery.bindValue( 0, nSeq );

    sqlQuery.exec();

    return 0;
}

int DBMgr::addConfigRec( ConfigRec& configRec )
{
    int i = 0;
    QSqlQuery sqlQuery;

    if( configRec.getNum() < 0 )
    {
        int nSeq = getNextVal( "TB_CONFIG" );
        configRec.setNum( nSeq );
    }

    sqlQuery.prepare( "INSERT INTO TB_CONFIG "
                      "( NUM, KIND, NAME, VALUE ) "
                      "VALUES( ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, configRec.getNum() );
    sqlQuery.bindValue( i++, configRec.getKind() );
    sqlQuery.bindValue( i++, configRec.getName() );
    sqlQuery.bindValue( i++, configRec.getValue() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::delConfigRec( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CONFIG WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::modConfigRec( int nNum, ConfigRec configRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CONFIG SET "
                      "KIND = ?, "
                      "NAME = ?, "
                      "VALUE = ? "
                      "WHERE NUM = ?;" );

    sqlQuery.bindValue( i++, configRec.getKind() );
    sqlQuery.bindValue( i++, configRec.getName() );
    sqlQuery.bindValue( i++, configRec.getValue() );
    sqlQuery.bindValue( i++, nNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::modConfigRec( int nKind, const QString strName, const QString strValue )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CONFIG SET "
                      "KIND = ?, "
                      "VALUE = ? "
                      "WHERE NAME = ?;" );

    sqlQuery.bindValue( i++, nKind );
    sqlQuery.bindValue( i++, strValue );
    sqlQuery.bindValue( i++, strName );

    sqlQuery.exec();
    return 0;
}

int DBMgr::getConfigRec( int nNum, ConfigRec& configRec )
{
    QList<ConfigRec> configList;
    QString strQuery = QString( "SELECT * FROM TB_CONFIG WHERE NUM = %1").arg( nNum );

    _getConfigList( strQuery, configList );
    if( configList.size() <= 0 ) return -1;

    configRec = configList.at(0);

    return 0;
}

int DBMgr::getConfigValue( int nKind, const QString& strName, QString& value )
{
    QString strQuery = QString( "SELECT Value FROM TB_CONFIG WHERE KIND = %1 AND NAME = '%2'").arg( nKind ).arg( strName );
    QSqlQuery SQL(strQuery);

    int nPosValue = SQL.record().indexOf( "Value" );

    if( SQL.next() )
    {
        value = SQL.value( nPosValue ).toString();
    }

    return 0;
}

int DBMgr::getConfigList( QList<ConfigRec>& configList )
{
    QString strQuery = QString("SELECT * FROM TB_CONFIG ORDER BY NUM DESC" );

    return _getConfigList( strQuery, configList );
}

int DBMgr::getConfigList( int nKind, QList<ConfigRec>& configList )
{
    QString strQuery = QString("SELECT * FROM TB_CONFIG WHERE KIND = %1 ORDER BY NUM DESC" ).arg(nKind);

    return _getConfigList( strQuery, configList );
}

int DBMgr::getKeyCountReq( int nKeyNum )
{
    int nCount = -1;
    if( nKeyNum < 0 ) return -1;

    QString strSQL = QString("SELECT COUNT(*) FROM TB_REQ WHERE KEY_NUM = %1").arg( nKeyNum );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}

int DBMgr::getKeyCountCert( int nKeyNum )
{
    int nCount = -1;
    if( nKeyNum < 0 ) return -1;

    QString strSQL = QString("SELECT COUNT(*) FROM TB_CERT WHERE KEYNUM = %1").arg( nKeyNum );
    QSqlQuery SQL(strSQL);

    while( SQL.next() )
    {
        nCount = SQL.value(0).toInt();
        return nCount;
    }

    return -1;
}
