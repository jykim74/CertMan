#ifndef DB_MGR_H
#define DB_MGR_H

#include <QtSql/QSqlDatabase>

#include "cert_rec.h"
#include "cert_policy_rec.h"
#include "crl_rec.h"
#include "crl_policy_rec.h"
#include "key_pair_rec.h"
#include "policy_ext_rec.h"
#include "req_rec.h"
#include "revoke_rec.h"

class CertRec;
class KeyPairRec;
class CRLRec;
class CertPolicyRec;
class CRLPolicyRec;
class ReqRec;
class PolicyExtRec;
class RevokeRec;

class DBMgr
{
public:
    DBMgr();

    int open( const QString dbPath );
    void close();

    int getCertRec( int nNum, CertRec cert );
    int getCertList( int nIssuerNum, QList<CertRec>& certList );
    int getCACertList( QList<CertRec>& certList );

    int getCRLList( int nIssuerNum, QList<CRLRec>& crlList );
    int getKeyPairList( QList<KeyPairRec>& keyPairList, int nStatus = -1 );
    int getKeyPairRec( int nNum, KeyPairRec& keyPairRec );
    int getReqList( QList<ReqRec>& reqList );
    int getReqRec( int nNum, ReqRec& reqRec );
    int getCRLRec( int nNum, CRLRec& crlRec );
    int getReqList( int nStatus, QList<ReqRec>& reqList );
    int getCertPolicyRec( int nNum, CertPolicyRec& certPolicy );
    int getCertPolicyList( QList<CertPolicyRec>& certPolicyList );
    int getCRLPolicyRec( int nNum, CRLPolicyRec& crlPolicy );
    int getCRLPolicyList( QList<CRLPolicyRec>& crlPolicyList );
    int getCertPolicyExtensionList( int nPolicyNum, QList<PolicyExtRec>& policyExtList );
    int getCRLPolicyExtensionList( int nPolicyNum, QList<PolicyExtRec>& policyExtList );
    int getRevokeRec( int nSeq, RevokeRec& revokeRec );

    int addKeyPairRec( KeyPairRec& keyPair );
    int addReqRec( ReqRec& reqRec );
    int addCertRec( CertRec& certRec );
    int addCRLRec( CRLRec& crlRec );
    int addCertPolicyRec( CertPolicyRec& certPolicyRec );
    int addCRLPolicyRec( CRLPolicyRec& crlPolicyRec );
    int addCertPolicyExtension( PolicyExtRec& policyExtension );
    int addCRLPolicyExtension( PolicyExtRec& policyExtension );
    int addRevokeRec( RevokeRec& revokeRec );

    int modReqStatus( int nSeq, int nStatus );
    int modCertStatus( int nNum, int nStatus );

    int getSeq( QString strTable );
    int getCertPolicyNextNum();
    int getCRLPolicyNextNum();

    int delCertPolicy( int nNum );
    int delCRLPolicy( int nNum );
    int delCertPolicyExtensionList( int nPolicyNum );
    int delCRLPolicyExtensionList( int nPolicyNum );

private:
    int _getCertList( QString strQuery, QList<CertRec>& certList );
    int _getKeyPairList( QString strQuery, QList<KeyPairRec>& keyPairList );
    int _getReqList( QString strQuery, QList<ReqRec>& reqList );
    int _getCertPolicyList( QString strQuery, QList<CertPolicyRec>& certPolicyList );
    int _getCRLList( QString strQuery, QList<CRLRec>& crlList );
    int _getCRLPolicyList( QString strQuery, QList<CRLPolicyRec>& crlPolicyList );
    int _getRevokeList( QString strQuery, QList<RevokeRec>& revokeList );
    int _getPolicyExtensionList( QString strQuery, QList<PolicyExtRec>& policyExtensionList );

private:
    QSqlDatabase   db_;
};

#endif // DB_MGR_H
