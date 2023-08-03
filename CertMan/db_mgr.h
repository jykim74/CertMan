#ifndef DB_MGR_H
#define DB_MGR_H

#include <QtSql/QSqlDatabase>

#include "cert_rec.h"
#include "cert_profile_rec.h"
#include "crl_rec.h"
#include "crl_profile_rec.h"
#include "key_pair_rec.h"
#include "profile_ext_rec.h"
#include "req_rec.h"
#include "revoke_rec.h"

class CertRec;
class KeyPairRec;
class CRLRec;
class CertProfileRec;
class CRLProfileRec;
class ReqRec;
class ProfileExtRec;
class RevokeRec;
class UserRec;
class SignerRec;
class KMSRec;
class KMSAttribRec;
class AuditRec;
class TSPRec;
class AdminRec;
class ConfigRec;

class DBMgr
{
public:
    DBMgr();

    int open( const QString dbPath );
    int remoteOpen( const QString strType, const QString strHost, const QString strUserName, const QString strPasswd, const QString strDBName );
    void close();
    bool isOpen();

    QString getNumName( int nNum, QString strTable, QString strColName );
//    QString getSeqName( int nSeq, QString strTable, QString strColName );

    int getCertCountAll();
    int getCRLCountAll();
    int getKeyPairCountAll();
    int getReqCountAll();

    int getCertCount( int nIssuerNum );
    int getCACount();
    int getCRLCount( int nIssuerNum );
    int getKeyPairCount( int nStatus );
    int getReqCount( int nStatus );
    int getRevokeCount( int nIssuerNum );
    int getUserCount();
    int getKMSCount();
    int getAuditCount();
    int getTSPCount();
    int getStatisticsCount( int nStartTime, int nEndTime, QString strTable );
    int getCertProfileCount( int nType = -1 );
    int getCRLProfileCount();

    int getCertSearchCount( int nIssuerNum, QString strTarget = nullptr, QString strWord = nullptr);
    int getCRLSearchCount( int nIssuerNum, QString strTarget = nullptr, QString strWord = nullptr );
    int getKeyPairSearchCount( int nStatus, QString strTarget, QString strWord );
    int getReqSearchCount( int nStatus, QString strTarget, QString strWord);
    int getRevokeSearchCount( int nIssuerNum, QString strTarget, QString strWord );
    int getUserSearchCount( QString strTarget, QString strWord );
    int getKMSSearchCount( QString strTarget, QString strWord);
    int getAuditSearchCount( QString strTarget, QString strWord);
    int getTSPSearchCount( QString strTarget, QString strWord);

    int getCertRec( int nNum, CertRec& cert );
    int getCertList( int nIssuerNum, QList<CertRec>& certList );
    int getCertList( int nIssuerNum, int nOffset, int nLimit, QList<CertRec>& certList );
    int getCertList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<CertRec>& certList );
    int getCertList( int nIssuerNum, QString strCRLDP, QList<CertRec>& certList );
    int getCACertList( QList<CertRec>& certList );
    int getCACertList( int nIssuerNum, QList<CertRec>& certList );
    int getCACertList( int nIssuerNum, QString strTarget, QString strWord, QList<CertRec>& certList );

    int getCRLList( int nIssuerNum, QList<CRLRec>& crlList );
    int getCRLList( int nIssuerNum, int nOffset, int nLimit, QList<CRLRec>& crlList );
    int getCRLList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<CRLRec>& crlList );

    int getKeyPairList( int nStatus, QList<KeyPairRec>& keyPairList );
    int getKeyPairList( int nStatus, int nOffset, int nLimit, QList<KeyPairRec>& keyPairList );
    int getKeyPairList( int nStatus, QString strTarget, QString strWord, int nOffset, int nLimit, QList<KeyPairRec>& keyPairList );
    int getKeyPairRec( int nNum, KeyPairRec& keyPairRec );

    int getReqRec( int nNum, ReqRec& reqRec );
    int getCRLRec( int nNum, CRLRec& crlRec );
    int getReqList( int nStatus, QList<ReqRec>& reqList );
    int getReqList( int nStatus, int nOffset, int nLimit, QList<ReqRec>& reqList );
    int getReqList( int nStatus, QString strTarget, QString strWord, int nOffset, int nLimit, QList<ReqRec>& reqList );

    int getAdminRec( int nSeq, AdminRec& adminRec );
    int getAdminList( QList<AdminRec>& adminList );

    int getCertProfileRec( int nNum, CertProfileRec& certProfile );
    int getCertProfileList( QList<CertProfileRec>& certProfileList );
    int getCertProfileListByType( int nType, QList<CertProfileRec>& certProfileList );
    int getCRLProfileRec( int nNum, CRLProfileRec& crlProfile );
    int getCRLProfileList( QList<CRLProfileRec>& crlProfileList );
    int getCertProfileExtensionList( int nProfileNum, QList<ProfileExtRec>& profileExtList );
    int getCRLProfileExtensionList( int nProfileNum, QList<ProfileExtRec>& profileExtList );
    int getRevokeRec( int nSeq, RevokeRec& revokeRec );
    int getRevokeRecByCertNum( int nCertNum, RevokeRec& revokeRec );

    int getRevokeList( int nIssuerNum, QList<RevokeRec>& revokeList );
    int getRevokeList( int nIssuerNum, int nOffset, int nLimit, QList<RevokeRec>& revokeList );
    int getRevokeList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<RevokeRec>& revokeList );
    int getRevokeList( int nIssuerNum, QString strCRLDP, QList<RevokeRec>& revokeList );

    int getUserList( QList<UserRec>& userList );
    int getUserList( int nOffset, int nLimit, QList<UserRec>& userList );
    int getUserList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<UserRec>& userList );

    int getKMSList( QList<KMSRec>& kmsList );
    int getKMSList( int nOffset, int nLimit, QList<KMSRec>& kmsList );
    int getKMSList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<KMSRec>& kmsList );

    int getKMSAttribList( int nNum, QList<KMSAttribRec>& kmsAttribList );

    int getAuditList( QList<AuditRec>& auditList );
    int getAuditList( int nOffset, int nLimit, QList<AuditRec>& auditList );
    int getAuditList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<AuditRec>& auditList );

    int getTSPList( QList<TSPRec>& tspList );
    int getTSPList( int nOffset, int nLimit, QList<TSPRec>& tspList );
    int getTSPList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<TSPRec>& tspList );

    int getUserRec( int nSeq, UserRec& userRec );
    int getKMSRec( int nSeq, KMSRec& kmsRec );
    int getAuditRec( int nSeq, AuditRec& auditRec );
    int getSignerList( int nType, QList<SignerRec>& signerList );
    int getSignerRec( int nNum, SignerRec& signerRec );
    int getTSPRec( int nSeq, TSPRec& tspRec );

    int getCRLDPListFromCert( int nIssuerNum, QList<QString>& crldpList );

    int addKeyPairRec( KeyPairRec& keyPair );
    int addReqRec( ReqRec& reqRec );
    int addCertRec( CertRec& certRec );
    int addCRLRec( CRLRec& crlRec );
    int addCertProfileRec( CertProfileRec& certProfileRec );
    int addCRLProfileRec( CRLProfileRec& crlProfileRec );
    int addCertProfileExtension( ProfileExtRec& profileExtension );
    int addCRLProfileExtension( ProfileExtRec& profileExtension );
    int addRevokeRec( RevokeRec& revokeRec );
    int addUserRec( UserRec& userRec );
    int addSignerRec( SignerRec& signerRec );
    int addKMSRec( KMSRec& kmsRec );
    int addAuditRec( AuditRec& auditRec );
    int addAdminRec( AdminRec& adminRec );

    int modKeyPairStatus( int nNum, int nStatus );
    int modReqStatus( int nSeq, int nStatus );
    int modCertStatus( int nNum, int nStatus );
    int modCertProfileRec( int nProfileNum, CertProfileRec profileRec );
    int modCRLProfileRec( int nProfileNum, CRLProfileRec profileRec );
    int modAdminRec( int nSeq, AdminRec adminRec );

 //   int getSeq( QString strTable );
    int getNextVal( const QString strTable );
    int getLastVal( const QString strTable );
    int getCertProfileNextNum();
    int getCRLProfileNextNum();

    int delCertProfile( int nNum );
    int delCRLProfile( int nNum );
    int delCertProfileExtensionList( int nProfileNum );
    int delCertProfileExtension( int nProfileNum, const QString strSN );
    int delCRLProfileExtensionList( int nProfileNum );
    int delCRLProfileExtension( int nProfileNum, const QString strSN );
    int delCertRec( int nNum );
    int delCRLRec( int nNum );
    int delKeyPairRec( int nNum );
    int delReqRec( int nNum );
    int delUserRec( int nNum );
    int delSignerRec( int nNum );
    int delKMSRec( int nSeq );
    int delAdminRec( int nSeq );

    int addConfigRec( ConfigRec& configRec );
    int delConfigRec( int nNum );
    int modConfigRec( int nNum, ConfigRec configRec );
    int getConfigRec( int nNum, ConfigRec& configRec );
    int getConfigValue( int nKind, const QString& strName, QString& value );
    int getConfigList( QList<ConfigRec>& configList );

    int getKeyCountReq( int nKeyNum );
    int getKeyCountCert( int nKeyNum );

private:
    int _getCertList( QString strQuery, QList<CertRec>& certList );
    int _getKeyPairList( QString strQuery, QList<KeyPairRec>& keyPairList );
    int _getReqList( QString strQuery, QList<ReqRec>& reqList );
    int _getCertProfileList( QString strQuery, QList<CertProfileRec>& certProfileList );
    int _getCRLList( QString strQuery, QList<CRLRec>& crlList );
    int _getCRLProfileList( QString strQuery, QList<CRLProfileRec>& crlProfileList );
    int _getRevokeList( QString strQuery, QList<RevokeRec>& revokeList );
    int _getProfileExtensionList( QString strQuery, QList<ProfileExtRec>& profileExtensionList );
    int _getUserList( QString strQuery, QList<UserRec>& userList );
    int _getSignerList( QString strQuery, QList<SignerRec>& signerList );
    int _getKMSList( QString strQuery, QList<KMSRec>& kmsList );
    int _getKMSAttribList( QString strQuery, QList<KMSAttribRec>& kmsAttribList );
    int _getAuditList( QString strQuery, QList<AuditRec>& auditList );
    int _getTSPList( QString strQuery, QList<TSPRec>& tspList );
    int _getAdminList( QString strQuery, QList<AdminRec>& adminList );
    int _getConfigList( QString strQuery, QList<ConfigRec>& configList );

private:
    QSqlDatabase    db_;
    QString         db_type_;
};

#endif // DB_MGR_H
