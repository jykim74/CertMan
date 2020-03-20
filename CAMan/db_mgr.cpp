#include <QSqlQuery>
#include <QtSql>

#include "db_mgr.h"
#include "cert_rec.h"
#include "cert_policy_rec.h"
#include "crl_rec.h"
#include "crl_policy_rec.h"
#include "key_pair_rec.h"
#include "policy_ext_rec.h"
#include "req_rec.h"
#include "revoke_rec.h"
#include "user_rec.h"
#include "signer_rec.h"

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

int DBMgr::getCertSearchCount( int nIssuerNum, QString strTarget, QString strWord )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CERT WHERE ISSUERNUM = %1 AND %2 LIKE '%%3%'" )
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

int DBMgr::getCRLSearchCount( int nIssuerNum, QString strTarget, QString strWord )
{
    int nCount = -1;

    QString strSQL = QString( "SELECT COUNT(*) FROM TB_CRL WHERE ISSUERNUM = %1 AND %2 LIKE '%%3%'" )
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

int DBMgr::getKeyPairSearchCount( int nStatus, QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_CRL WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    if( nStatus >= 0 ) strSQL += QString( " AND STATUS = %1" ).arg( nStatus );

    return -1;
}

int DBMgr::getReqSearchCount( int nStatus, QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_REQ WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    if( nStatus >= 0 ) strSQL += QString( " AND STATUS = %1" ).arg( nStatus );

    return -1;
}

int DBMgr::getRevokeSearchCount( int nIssuerNum, QString strTarget, QString strWord )
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_REVOKED WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    return -1;
}

int DBMgr::getUserSearchCount( QString strTarget, QString strWord)
{
    int nCount = -1;
    QString strSQL = QString("SELECT COUNT(*) FROM TB_USER WHERE %1 LIKE '%%2%'")
            .arg( strTarget )
            .arg( strWord );

    return -1;
}

int DBMgr::getCACertList( QList<CertRec>& certList )
{
    QString strSQL  = "SELECT * FROM TB_CERT WHERE ISCA=1 ORDER BY NUM DESC";

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

int DBMgr::getUserRec( int nSeq, UserRec& userRec )
{
    QList<UserRec> userList;
    QString strQuery = QString( "SELECT * FROM TB_USER WHERE NUM = %1").arg(nSeq);

    _getUserList( strQuery, userList );
    if( userList.size() <= 0 ) return -1;

    userRec = userList.at(0);

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

    strSQL.sprintf( "SELECT * FROM TB_REQ" );
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
    int nPosKeyNum = SQL.record().indexOf( "KEY_NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosDN = SQL.record().indexOf( "DN" );
    int nPosCSR = SQL.record().indexOf( "CSR" );
    int nPosHash = SQL.record().indexOf( "HASH" );
    int nPosStatus = SQL.record().indexOf( "Status" );

    while ( SQL.next()) {
        ReqRec reqRec;

        reqRec.setSeq( SQL.value(nPosSeq).toInt() );
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

int DBMgr::addKeyPairRec(KeyPairRec& keyPair)
{
    QSqlQuery query;

    query.prepare( "INSERT INTO TB_KEY_PAIR "
                   "(NUM, ALGORITHM, NAME, PUBLIC, PRIVATE, PARAM, STATUS ) "
                   "VALUES ( null, ?, ?, ?, ?, ?, ? )" );

    query.bindValue(0, keyPair.getAlg() );
    query.bindValue(1, keyPair.getName() );
    query.bindValue(2, keyPair.getPublicKey() );
    query.bindValue(3, keyPair.getPrivateKey() );
    query.bindValue(4, keyPair.getParam() );
    query.bindValue(5, keyPair.getStatus() );

    bool res = query.exec();

    if( res == false )
    {
        qDebug() << query.lastError();
        return -1;
    }

    return 0;
}

int DBMgr::addReqRec( ReqRec& reqRec )
{
    QSqlQuery query;

    query.prepare( "INSERT INTO TB_REQ "
                   "(SEQ, KEY_NUM, NAME, DN, CSR, HASH, STATUS ) "
                   "VALUES( null, ?, ?, ?, ?, ?, ? )" );

    query.bindValue( 0, reqRec.getKeyNum() );
    query.bindValue( 1, reqRec.getName() );
    query.bindValue( 2, reqRec.getDN() );
    query.bindValue( 3, reqRec.getCSR() );
    query.bindValue( 4, reqRec.getHash() );
    query.bindValue( 5, reqRec.getStatus() );

    query.exec();
    return 0;
}

int DBMgr::getCertPolicyList( QList<CertPolicyRec>& certPolicyList )
{
    QString strSQL = "SELECT * FROM TB_CERT_POLICY ORDER BY NUM DESC";

    return _getCertPolicyList( strSQL, certPolicyList );
}


int DBMgr::getCertPolicyRec( int nNum, CertPolicyRec& certPolicy )
{
    QString strSQL;
    strSQL.sprintf( "SELECT * FROM TB_CERT_POLICY WHERE NUM = %d", nNum );

    QList<CertPolicyRec> certPolicyList;

    _getCertPolicyList( strSQL, certPolicyList );
    if( certPolicyList.size() <= 0 ) return -1;

    certPolicy = certPolicyList.at(0);

    return 0;
}

int DBMgr::getCRLPolicyRec( int nNum, CRLPolicyRec& crlPolicy )
{
    QString strSQL;
    strSQL.sprintf( "SELECT * FROM TB_CRL_POLICY WHERE NUM = %d", nNum );

    QList<CRLPolicyRec> crlPolicyList;

    _getCRLPolicyList( strSQL, crlPolicyList );
    if( crlPolicyList.size() <= 0 ) return -1;

    crlPolicy = crlPolicyList.at(0);

    return 0;
}

int DBMgr::_getCertPolicyList( QString strQuery, QList<CertPolicyRec>& certPolicyList )
{
    int iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosVersion = SQL.record().indexOf( "VERSION" );
    int nPosNotBefore = SQL.record().indexOf( "NotBefore" );
    int nPosNotAfter = SQL.record().indexOf( "NotAfter" );
    int nPosHash = SQL.record().indexOf( "HASH" );
    int nPosDNTemplate = SQL.record().indexOf( "DNTemplate" );

    while( SQL.next() )
    {
        CertPolicyRec certPolicy;

        certPolicy.setNum( SQL.value(nPosNum).toInt() );
        certPolicy.setName( SQL.value(nPosName).toString() );
        certPolicy.setVersion( SQL.value(nPosVersion).toInt() );
        certPolicy.setNotBefore( SQL.value(nPosNotBefore).toInt() );
        certPolicy.setNotAfter( SQL.value(nPosNotAfter).toInt() );
        certPolicy.setHash( SQL.value(nPosHash).toString() );
        certPolicy.setDNTemplate( SQL.value(nPosDNTemplate).toString() );

        certPolicyList.append( certPolicy );
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
    int nPosCRL = SQL.record().indexOf( "CRL" );

    while( SQL.next() )
    {
        CRLRec crlRec;

        crlRec.setNum( SQL.value(nPosNum).toInt() );
        crlRec.setRegTime( SQL.value(nPosRegTime).toInt());
        crlRec.setIssuerNum( SQL.value(nPosIssuerNum).toInt() );
        crlRec.setSignAlg( SQL.value(nPosSignAlg).toString() );
        crlRec.setCRL( SQL.value(nPosCRL).toString() );

        crlList.append( crlRec );
        iCount++;
    }

    SQL.finish();
    return 0;
}

int DBMgr::getCRLPolicyList(QList<CRLPolicyRec>& crlPolicyList)
{
    QString strSQL = "SELECT * FROM TB_CRL_POLICY ORDER BY NUM DESC";

    return _getCRLPolicyList( strSQL, crlPolicyList );
}

int DBMgr::_getCRLPolicyList( QString strQuery, QList<CRLPolicyRec>& crlPolicyList )
{
    int iCount = 0;
    QSqlQuery SQL(strQuery);

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosVersion = SQL.record().indexOf( "VERSION" );
    int nPosLastUpdate = SQL.record().indexOf( "LASTUPDATE" );
    int nPosNextUpdate = SQL.record().indexOf( "NEXTUPDATE" );
    int nPosHash = SQL.record().indexOf( "HASH" );

    while( SQL.next() )
    {
        CRLPolicyRec crlPolicy;

        crlPolicy.setNum( SQL.value(nPosNum).toInt() );
        crlPolicy.setName( SQL.value(nPosName).toString() );
        crlPolicy.setVersion( SQL.value(nPosVersion).toInt() );
        crlPolicy.setLastUpdate( SQL.value(nPosLastUpdate).toInt() );
        crlPolicy.setNextUpdate( SQL.value(nPosNextUpdate).toInt() );
        crlPolicy.setHash( SQL.value(nPosHash).toString() );

        crlPolicyList.append( crlPolicy );
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

int DBMgr::getCertPolicyExtensionList( int nPolicyNum, QList<PolicyExtRec>& policyExtList )
{
    QString strQuery = QString( "SELECT * FROM TB_CERT_POLICY_EXTENSION WHERE POLICYNUM = %1").arg( nPolicyNum );

    return _getPolicyExtensionList( strQuery, policyExtList );
}

int DBMgr::getCRLPolicyExtensionList( int nPolicyNum, QList<PolicyExtRec>& policyExtList )
{
    QString strQuery = QString( "SELECT * FROM TB_CRL_POLICY_EXTENSION WHERE POLICYNUM = %1").arg( nPolicyNum );

    return _getPolicyExtensionList( strQuery, policyExtList );
}

int DBMgr::_getPolicyExtensionList( QString strQuery, QList<PolicyExtRec>& policyExtensionList )
{
    int iCount = 0;
    QSqlQuery SQL(strQuery);

    int nPosSeq = SQL.record().indexOf( "SEQ" );
    int nPosPolicyNum = SQL.record().indexOf( "POLICYNUM" );
    int nPosCritical = SQL.record().indexOf( "CRITICAL" );
    int nPosSN = SQL.record().indexOf( "SN" );
    int nPosValue = SQL.record().indexOf( "VALUE" );

    while( SQL.next() )
    {
        PolicyExtRec policyExtension;

        policyExtension.setSeq( SQL.value(nPosSeq).toInt() );
        policyExtension.setPolicyNum( SQL.value(nPosPolicyNum).toInt() );
        policyExtension.setCritical( SQL.value(nPosCritical).toBool() );
        policyExtension.setSN( SQL.value(nPosSN).toString() );
        policyExtension.setValue( SQL.value(nPosValue).toString() );

        policyExtensionList.append( policyExtension );
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
    int nPosDesc = SQL.record().indexOf( "DESC" );

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
        signer.setDesc( SQL.value(nPosDesc).toString());

        signerList.append( signer );
    }

    SQL.finish();
    return 0;
}

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

int DBMgr::addCertRec( CertRec& certRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CERT "
                      "( NUM, REGTIME, KEYNUM, USERNUM, SIGNALG, CERT, ISSELF, ISCA, ISSUERNUM, SUBJECTDN, STATUS, SERIAL, DNHASH, KEYHASH, CRLDP ) "
                      "VALUES( null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? );" );

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

    sqlQuery.exec();
    return 0;
}
int DBMgr::modKeyPairStatus( int nNum, int nStatus )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_KEY_PAIR SET STATUS = ? WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, nStatus );
    sqlQuery.bindValue( 1, nNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::modReqStatus( int nSeq, int nStatus )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_REQ SET STATUS = ? WHERE SEQ = ?;" );

    sqlQuery.bindValue( 0, nStatus );
    sqlQuery.bindValue( 1, nSeq );

    sqlQuery.exec();
    return 0;
}

int DBMgr::modCertStatus( int nNum, int nStatus )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CERT SET STATUS = ? WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, nStatus );
    sqlQuery.bindValue( 1, nNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::modCertPolicyRec( int nPolicyNum, CertPolicyRec policyRec )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CERT_POLICY SET "
                      "NAME = ?, "
                      "VERSION = ?, "
                      "NOTBEFORE = ?, "
                      "NOTAFTER = ?, "
                      "HASH = ?, "
                      "DNTemplate = ? "
                      "WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, policyRec.getName() );
    sqlQuery.bindValue( 1, policyRec.getVersion() );
    sqlQuery.bindValue( 2, (int)policyRec.getNotBefore() );
    sqlQuery.bindValue( 3, (int)policyRec.getNotAfter() );
    sqlQuery.bindValue( 4, policyRec.getHash() );
    sqlQuery.bindValue( 5, policyRec.getDNTemplate() );
    sqlQuery.bindValue( 6, nPolicyNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::modCRLPolicyRec( int nPolicyNum, CRLPolicyRec policyRec )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "UPDATE TB_CRL_POLICY SET "
                      "NAME = ?, "
                      "VERSION = ?, "
                      "LASTUPDATE = ?, "
                      "NEXTUPDATE = ?, "
                      "HASH = ? "
                      "WHERE NUM = ?;" );

    sqlQuery.bindValue( 0, policyRec.getName() );
    sqlQuery.bindValue( 1, policyRec.getVersion() );
    sqlQuery.bindValue( 2, (int)policyRec.getLastUpdate() );
    sqlQuery.bindValue( 3, (int)policyRec.getNextUpdate() );
    sqlQuery.bindValue( 4, policyRec.getHash() );
    sqlQuery.bindValue( 5, nPolicyNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addCRLRec( CRLRec& crlRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CRL "
                      "( NUM, REGTIME, ISSUERNUM, SIGNALG, CRL ) "
                      "VALUES( null,?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, crlRec.getRegTime() );
    sqlQuery.bindValue( i++, crlRec.getIssuerNum() );
    sqlQuery.bindValue( i++, crlRec.getSignAlg() );
    sqlQuery.bindValue( i++, crlRec.getCRL() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addCertPolicyRec( CertPolicyRec& certPolicyRec )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CERT_POLICY "
                      "( NUM, NAME, VERSION, NOTBEFORE, NOTAFTER, HASH, DNTEMPLATE ) "
                      "VALUES( ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, certPolicyRec.getNum() );
    sqlQuery.bindValue( 1, certPolicyRec.getName() );
    sqlQuery.bindValue( 2, certPolicyRec.getVersion() );
    sqlQuery.bindValue( 3, QString( "%1" ).arg( certPolicyRec.getNotBefore() ) );
    sqlQuery.bindValue( 4, QString( "%1").arg( certPolicyRec.getNotAfter() ) );
    sqlQuery.bindValue( 5, certPolicyRec.getHash() );
    sqlQuery.bindValue( 6, certPolicyRec.getDNTemplate() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addCRLPolicyRec( CRLPolicyRec& crlPolicyRec )
{
    QSqlQuery sqlQuery;

    sqlQuery.prepare( "INSERT INTO TB_CRL_POLICY "
                      "( NUM, NAME, VERSION, LASTUPDATE, NEXTUPDATE, HASH ) "
                      "VALUES( ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, crlPolicyRec.getNum() );
    sqlQuery.bindValue( 1, crlPolicyRec.getName() );
    sqlQuery.bindValue( 2, crlPolicyRec.getVersion() );
    sqlQuery.bindValue( 3, QString("%1").arg(crlPolicyRec.getLastUpdate()));
    sqlQuery.bindValue( 4, QString("%1").arg(crlPolicyRec.getNextUpdate()));
    sqlQuery.bindValue( 5, crlPolicyRec.getHash());

    sqlQuery.exec();
    return 0;
}

int DBMgr::getCertPolicyNextNum()
{
    int nNextNum = -1;

    QString strSQL;
    strSQL.sprintf( "SELECT MAX(num)+1 FROM TB_CERT_POLICY" );
    QSqlQuery query( strSQL );

    while( query.next() )
    {
        nNextNum = query.value(0).toInt();
        break;
    }

    query.finish();
    return nNextNum;
}

int DBMgr::getCRLPolicyNextNum()
{
    int nNextNum = -1;

    QString strSQL;
    strSQL.sprintf( "SELECT MAX(num)+1 FROM TB_CRL_POLICY" );
    QSqlQuery query( strSQL );

    while( query.next() )
    {
        nNextNum = query.value(0).toInt();
        break;
    }

    query.finish();
    return nNextNum;
}

int DBMgr::addCertPolicyExtension( PolicyExtRec& policyExtension )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CERT_POLICY_EXTENSION "
                      "( SEQ, POLICYNUM, CRITICAL, SN, VALUE ) "
                      "VALUES( null, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, policyExtension.getPolicyNum() );
    sqlQuery.bindValue( 1, policyExtension.isCritical() );
    sqlQuery.bindValue( 2, policyExtension.getSN() );
    sqlQuery.bindValue( 3, policyExtension.getValue() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addCRLPolicyExtension( PolicyExtRec& policyExtension )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CRL_POLICY_EXTENSION "
                      "( SEQ, POLICYNUM, CRITICAL, SN, VALUE ) "
                      "VALUES( null, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, policyExtension.getPolicyNum() );
    sqlQuery.bindValue( 1, policyExtension.isCritical() );
    sqlQuery.bindValue( 2, policyExtension.getSN() );
    sqlQuery.bindValue( 3, policyExtension.getValue() );

    sqlQuery.exec();
    return 0;
}


int DBMgr::addRevokeRec( RevokeRec& revokeRec )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_REVOKED "
                      "( SEQ, CERTNUM, ISSUERNUM, SERIAL, REVOKEDDATE, REASON, CRLDP ) "
                      "VALUES( null, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, revokeRec.getCertNum() );
    sqlQuery.bindValue( 1, revokeRec.getIssuerNum() );
    sqlQuery.bindValue( 2, revokeRec.getSerial() );
    sqlQuery.bindValue( 3, revokeRec.getRevokeDate() );
    sqlQuery.bindValue( 4, revokeRec.getReason() );
    sqlQuery.bindValue( 5, revokeRec.getCRLDP() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addUserRec(UserRec &userRec)
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_USER "
                      "( NUM, REGTIME, NAME, SSN, EMAIL, STATUS, REFNUM, AUTHCODE ) "
                      "VALUES( null, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, userRec.getRegTime() );
    sqlQuery.bindValue( i++, userRec.getName() );
    sqlQuery.bindValue( i++, userRec.getSSN() );
    sqlQuery.bindValue( i++, userRec.getEmail() );
    sqlQuery.bindValue( i++, userRec.getStatus() );
    sqlQuery.bindValue( i++, userRec.getRefNum() );
    sqlQuery.bindValue( i++, userRec.getAuthCode() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addSignerRec( SignerRec& signerRec )
{
    int i = 0;
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_SIGNER "
                      "( NUM, REGTIME, TYPE, DN, DNHASH, STATUS, CERT, DESC ) "
                      "VALUES( null, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( i++, signerRec.getRegTime() );
    sqlQuery.bindValue( i++, signerRec.getType() );
    sqlQuery.bindValue( i++, signerRec.getDN() );
    sqlQuery.bindValue( i++, signerRec.getDNHash() );
    sqlQuery.bindValue( i++, signerRec.getStatus() );
    sqlQuery.bindValue( i++, signerRec.getCert() );
    sqlQuery.bindValue( i++, signerRec.getDesc() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::delCertPolicy( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CERT_POLICY WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();
    return 0;
}

int DBMgr::delCRLPolicy( int nNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CRL_POLICY WHERE NUM = ?");

    sqlQuery.bindValue( 0, nNum );

    sqlQuery.exec();

    return 0;
}

int DBMgr::delCertPolicyExtensionList( int nPolicyNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CERT_POLICY_EXTENSION WHERE POLICYNUM = ?");

    sqlQuery.bindValue( 0, nPolicyNum );

    sqlQuery.exec();
}

int DBMgr::delCRLPolicyExtensionList( int nPolicyNum )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "DELETE FROM TB_CRL_POLICY_EXTENSION WHERE POLICYNUM = ?");

    sqlQuery.bindValue( 0, nPolicyNum );

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
