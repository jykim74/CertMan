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
    int nPosKeyNum = SQL.record().indexOf( "KeyNum" );
    int nPosSignAlg = SQL.record().indexOf( "SignAlg" );
    int nPosCert = SQL.record().indexOf( "CERT" );
    int nPosSelf = SQL.record().indexOf( "IsSelf" );
    int nPosCA = SQL.record().indexOf( "IsCA" );
    int nPosIssuerNum = SQL.record().indexOf( "IssuerNum" );
    int nPosSubjectDN = SQL.record().indexOf( "SubjectDN" );
    int nPosStatus = SQL.record().indexOf( "Status" );

    while( SQL.next() )
    {
        CertRec certRec;

        certRec.setNum( SQL.value(nPosNum).toInt() );
        certRec.setKeyNum( SQL.value(nPosKeyNum).toInt());
        certRec.setSignAlg( SQL.value(nPosSignAlg).toString() );
        certRec.setCert( SQL.value(nPosCert).toString() );
        certRec.setSelf( SQL.value(nPosSelf).toBool() );
        certRec.setCA( SQL.value(nPosCA).toBool() );
        certRec.setIssuerNum( SQL.value(nPosIssuerNum).toInt());
        certRec.setSubjectDN( SQL.value(nPosSubjectDN).toString() );
        certRec.setStatus( SQL.value(nPosStatus).toInt());

        certList.append( certRec );
        iCount++;
    }

    SQL.finish();

    if( iCount == 0 ) return -1;

    return 0;
}

int DBMgr::getCACertList( QList<CertRec>& certList )
{
    QString strSQL  = "SELECT * FROM TB_CERT WHERE ISCA=1";

    return _getCertList( strSQL, certList );
}

int DBMgr::getCertRec( int nNum, CertRec cert )
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
    strSQL = QString( "SELECT * FROM TB_CERT WHERE ISSUERNUM = %1" ).arg( nIssuerNum );

    return _getCertList( strSQL, certList );
}

int DBMgr::getKeyPairList( QList<KeyPairRec>& keyPairList, int nStatus )
{
    QString strSQL = "";
    strSQL = QString( "SELECT * FROM TB_KEY_PAIR" );

    if( nStatus >= 0 ) strSQL += QString( " WHERE STATUS = %1" ).arg( nStatus );

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

int DBMgr::getReqList(QList<ReqRec> &reqList)
{
    QString strQuery = "SELECT * FROM TB_REQ";

    return _getReqList( strQuery, reqList );
}

int DBMgr::getReqList( int nStatus, QList<ReqRec>& reqList )
{
    QString strQuery;

    strQuery.sprintf( "SELECT * FROM TB_REQ STATUS = %d", nStatus );

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
    query.bindValue(4, keyPair.getStatus() );

    query.exec();

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
    QString strSQL = "SELECT * FROM TB_CERT_POLICY";

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

int DBMgr::_getCertPolicyList( QString strQuery, QList<CertPolicyRec>& certPolicyList )
{
    int iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosName = SQL.record().indexOf( "NAME" );
    int nPosVersion = SQL.record().indexOf( "VERSION" );
    int nPosNotBefore = SQL.record().indexOf( "ValidFrom" );
    int nPosNotAfter = SQL.record().indexOf( "ValidTo" );
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
    QString strSQL = QString( "SELECT * FROM TB_CRL WHERE ISSUERNUM = %1" ).arg( nIssuerNum );

    return _getCRLList( strSQL, crlList );
}

int DBMgr::_getCRLList( QString strQuery, QList<CRLRec>& crlList )
{
    int iCount = 0;
    QSqlQuery SQL( strQuery );

    int nPosNum = SQL.record().indexOf( "NUM" );
    int nPosIssuerNum = SQL.record().indexOf( "IssuerNum" );
    int nPosSignAlg = SQL.record().indexOf( "SignAlg" );
    int nPosCRL = SQL.record().indexOf( "CRL" );

    while( SQL.next() )
    {
        CRLRec crlRec;

        crlRec.setNum( SQL.value(nPosNum).toInt() );
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
    QString strSQL = "SELECT * FROM TB_CRL_POLICY";

    return _getCRLPolicyList( strSQL, crlPolicyList );
}

int DBMgr::_getCRLPolicyList( QString strQuery, QList<CRLPolicyRec>& crlPolicyList )
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
        CRLPolicyRec crlPolicy;

        crlPolicy.setNum( SQL.value(nPosNum).toInt() );
        crlPolicy.setName( SQL.value(nPosName).toString() );
        crlPolicy.setVersion( SQL.value(nPosVersion).toInt() );
        crlPolicy.setThisUpdate( SQL.value(nPosThisUpdate).toInt() );
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

    while( SQL.next() )
    {
        RevokeRec revokeRec;

        revokeRec.setSeq( SQL.value(nPosSeq).toInt() );
        revokeRec.setCertNum( SQL.value(nPosCertNum).toInt() );
        revokeRec.setIssuerNum( SQL.value(nPosIssuerNum).toInt() );
        revokeRec.setSerial( SQL.value(nPosSerial).toString() );
        revokeRec.setRevokeDate( SQL.value(nPosRevokeDate).toInt() );
        revokeRec.setReason( SQL.value(nPosReason).toInt() );

        revokeList.append( revokeRec );
        iCount++;
    }

    SQL.finish();
    return 0;
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
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CERT "
                      "( NUM, KEYNUM, SIGNALG, CERT, ISSELF, ISCA, ISSUERNUM, SUBJECTDN, STATUS ) "
                      "VALUES( null, ?, ?, ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, certRec.getKeyNum() );
    sqlQuery.bindValue( 1, certRec.getSignAlg() );
    sqlQuery.bindValue( 2, certRec.getCert() );
    sqlQuery.bindValue( 3, certRec.isSelf() );
    sqlQuery.bindValue( 4, certRec.isCA() );
    sqlQuery.bindValue( 5, certRec.getIssuerNum() );
    sqlQuery.bindValue( 6, certRec.getSubjectDN() );
    sqlQuery.bindValue( 7, certRec.getStatus() );

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

int DBMgr::addCRLRec( CRLRec& crlRec )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CRL "
                      "( NUM, ISSUERNUM, SIGNALG, CRL ) "
                      "VALUES( null, ?, ?, ? );" );

    sqlQuery.bindValue( 0, crlRec.getIssuerNum() );
    sqlQuery.bindValue( 1, crlRec.getSignAlg() );
    sqlQuery.bindValue( 2, crlRec.getCRL() );

    sqlQuery.exec();
    return 0;
}

int DBMgr::addCertPolicyRec( CertPolicyRec& certPolicyRec )
{
    QSqlQuery sqlQuery;
    sqlQuery.prepare( "INSERT INTO TB_CERT_POLICY "
                      "( NUM, NAME, VERSION, VALIDFROM, VALIDTO, HASH, DNTEMPLATE ) "
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
                      "( NUM, NAME, VERSION, THISUPDATE, NEXTUPDATE, HASH ) "
                      "VALUES( ?, ?, ?, ?, ?, ? );" );

    sqlQuery.bindValue( 0, crlPolicyRec.getNum() );
    sqlQuery.bindValue( 1, crlPolicyRec.getName() );
    sqlQuery.bindValue( 2, crlPolicyRec.getVersion() );
    sqlQuery.bindValue( 3, QString("%1").arg(crlPolicyRec.getThisUpdate()));
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
                      "( SEQ, CERTNUM, ISSUERNUM, SERIAL, REVOKEDDATE, REASON ) "
                      "VALUES( null, ?, ?, ?, ?, ?);" );

    sqlQuery.bindValue( 0, revokeRec.getCertNum() );
    sqlQuery.bindValue( 1, revokeRec.getIssuerNum() );
    sqlQuery.bindValue( 2, revokeRec.getSerial() );
    sqlQuery.bindValue( 3, revokeRec.getRevokeDate() );
    sqlQuery.bindValue( 4, revokeRec.getReason() );

    sqlQuery.exec();
    return 0;
}
