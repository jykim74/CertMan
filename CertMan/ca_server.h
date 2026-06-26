#ifndef CA_SERVER_H
#define CA_SERVER_H

#include <QObject>

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>

#include "js_bin.h"
#include "js_pkcs11.h"
#include "js_cmp.h"
#include "js_scep.h"
#include "js_pki_x509.h"
#include "js_cmp.h"

#include "db_mgr.h"
#include "js_cmp_srv.h"

class CAServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit CAServer( QObject *parent = nullptr );
    ~CAServer();

    void startServer( int nPort );
    void setLogEdit( QPlainTextEdit *pEdit );
    void setCACert( const BIN *pCert );
    void setCANum( int nNum );
    void setProfileNum( int nNum );
    void setCAPriKey( const BIN *pPriKey, bool bP11 = false );

public slots:
    int readReady();

private :
    int procCMP( const BIN *pReq, BIN *pRsp );
    int procSCEP( const JNameValList *pParamList, const BIN *pReq, BIN *pRsp );

private:
    QPlainTextEdit* log_edit_;

    int ca_num_;
    int profile_num_;
    BIN ca_cert_;
    BIN ca_pri_key_;
    QTcpSocket *client_;
    bool p11_;

protected:
    void incomingConnection( qintptr socketDescriptor );
    int workSCEPOperation( const BIN *pPKIReq, BIN *pCertRsp );
    int runSCEP_PKIReq( const BIN *pSignCert, const BIN *pData, BIN *pSignedData );
    int runSCEP_GetCRL( const BIN *pSignCert, const BIN *pData, BIN *pSignedData );

    int runCMP_GENM( void *pSrvCTX, const BIN *pReq, const QString strAuthCode, const BIN *pSignCert, const JStrList *pITAVList, BIN *pRsp );
    int runCMP_IR( void *pSrvCTX, const BIN *pReq, const QString strAuthCode, const BIN *pPubKey,const QString strDN,BIN *pRsp );

    int runCMP_P10CR( void *pSrvCTX, const BIN *pReq, const QString strAuthCode, const BIN *pPubKey,const QString strDN,BIN *pRsp );
    int runCMP_RR( void *pSrvCTX, const BIN *pReq, CertRec certRec, int nReason, BIN *pRsp );
    int runCMP_KUR( void *pSrvCTX, const BIN *pReq, CertRec certRec, const BIN *pPubKey, BIN *pRsp );
    int runCMP_CertConf( void *pSrvCTX, const BIN *pReq, BIN *pRsp );

    int makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );

    int setITAVValue( const JStrList *pOIDList, JNumBINList **ppValueList );
    int getRootCA( BIN *pRootCA );
    int getChainList( BINList **ppChainList );
};

#endif // CA_SERVER_H
