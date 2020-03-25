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
class UserRec;
class SignerRec;

class DBMgr
{
public:
    DBMgr();

    int open( const QString dbPath );
    void close();

    int getCertCount( int nIssuerNum );
    int getCRLCount( int nIssuerNum );
    int getKeyPairCount( int nStatus );
    int getReqCount( int nStatus );
    int getRevokeCount( int nIssuerNum );
    int getUserCount();

    int getCertSearchCount( int nIssuerNum, QString strTarget, QString strWord );
    int getCRLSearchCount( int nIssuerNum, QString strTarget, QString strWord );
    int getKeyPairSearchCount( int nStatus, QString strTarget, QString strWord);
    int getReqSearchCount( int nStatus, QString strTarget, QString strWord);
    int getRevokeSearchCount( int nIssuerNum, QString strTarget, QString strWord );
    int getUserSearchCount( QString strTarget, QString strWord);

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

    int getCertPolicyRec( int nNum, CertPolicyRec& certPolicy );
    int getCertPolicyList( QList<CertPolicyRec>& certPolicyList );
    int getCRLPolicyRec( int nNum, CRLPolicyRec& crlPolicy );
    int getCRLPolicyList( QList<CRLPolicyRec>& crlPolicyList );
    int getCertPolicyExtensionList( int nPolicyNum, QList<PolicyExtRec>& policyExtList );
    int getCRLPolicyExtensionList( int nPolicyNum, QList<PolicyExtRec>& policyExtList );
    int getRevokeRec( int nSeq, RevokeRec& revokeRec );
    int getRevokeRecByCertNum( int nCertNum, RevokeRec& revokeRec );

    int getRevokeList( int nIssuerNum, QList<RevokeRec>& revokeList );
    int getRevokeList( int nIssuerNum, int nOffset, int nLimit, QList<RevokeRec>& revokeList );
    int getRevokeList( int nIssuerNum, QString strTarget, QString strWord, int nOffset, int nLimit, QList<RevokeRec>& revokeList );
    int getRevokeList( int nIssuerNum, QString strCRLDP, QList<RevokeRec>& revokeList );

    int getUserList( QList<UserRec>& userList );
    int getUserList( int nOffset, int nLimit, QList<UserRec>& userList );
    int getUserList( QString strTarget, QString strWord, int nOffset, int nLimit, QList<UserRec>& userList );

    int getUserRec( int nSeq, UserRec& userRec );
    int getSignerList( int nType, QList<SignerRec>& signerList );
    int getSignerRec( int nNum, SignerRec& signerRec );

    int getCRLDPListFromCert( int nIssuerNum, QList<QString>& crldpList );

    int addKeyPairRec( KeyPairRec& keyPair );
    int addReqRec( ReqRec& reqRec );
    int addCertRec( CertRec& certRec );
    int addCRLRec( CRLRec& crlRec );
    int addCertPolicyRec( CertPolicyRec& certPolicyRec );
    int addCRLPolicyRec( CRLPolicyRec& crlPolicyRec );
    int addCertPolicyExtension( PolicyExtRec& policyExtension );
    int addCRLPolicyExtension( PolicyExtRec& policyExtension );
    int addRevokeRec( RevokeRec& revokeRec );
    int addUserRec( UserRec& userRec );
    int addSignerRec( SignerRec& signerRec );

    int modKeyPairStatus( int nNum, int nStatus );
    int modReqStatus( int nSeq, int nStatus );
    int modCertStatus( int nNum, int nStatus );
    int modCertPolicyRec( int nPolicyNum, CertPolicyRec policyRec );
    int modCRLPolicyRec( int nPolicyNum, CRLPolicyRec policyRec );

    int getSeq( QString strTable );
    int getCertPolicyNextNum();
    int getCRLPolicyNextNum();

    int delCertPolicy( int nNum );
    int delCRLPolicy( int nNum );
    int delCertPolicyExtensionList( int nPolicyNum );
    int delCRLPolicyExtensionList( int nPolicyNum );
    int delCertRec( int nNum );
    int delCRLRec( int nNum );
    int delKeyPairRec( int nNum );
    int delReqRec( int nNum );
    int delUserRec( int nNum );
    int delSignerRec( int nNum );

private:
    int _getCertList( QString strQuery, QList<CertRec>& certList );
    int _getKeyPairList( QString strQuery, QList<KeyPairRec>& keyPairList );
    int _getReqList( QString strQuery, QList<ReqRec>& reqList );
    int _getCertPolicyList( QString strQuery, QList<CertPolicyRec>& certPolicyList );
    int _getCRLList( QString strQuery, QList<CRLRec>& crlList );
    int _getCRLPolicyList( QString strQuery, QList<CRLPolicyRec>& crlPolicyList );
    int _getRevokeList( QString strQuery, QList<RevokeRec>& revokeList );
    int _getPolicyExtensionList( QString strQuery, QList<PolicyExtRec>& policyExtensionList );
    int _getUserList( QString strQuery, QList<UserRec>& userList );
    int _getSignerList( QString strQuery, QList<SignerRec>& signerList );

private:
    QSqlDatabase   db_;
};

#endif // DB_MGR_H
