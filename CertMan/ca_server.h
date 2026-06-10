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
    void setCAPriKey( const BIN *pPriKey );

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

protected:
    void incomingConnection( qintptr socketDescriptor );
    int workSCEPOperation( const BIN *pPKIReq, BIN *pCertRsp );
    int runSCEP_PKIReq( const BIN *pSignCert, const BIN *pData, BIN *pSignedData );
    int runSCEP_GetCRL( const BIN *pSignCert, const BIN *pData, BIN *pSignedData );

    int runCMP_GENM( void *pCTX, void *pBody );
    int runCMP_IR( void *pCTX, UserRec *pDBUser, void *pBody, BIN *pNewCert );
    int runCMP_P10CR( void *pCTX, UserRec *pDBUser, void *pBody, BIN *pNewCert );
    int runCMP_RR( void *pCTX, CertRec *pDBCert, void *pBody );
    int runCMP_KUR( void *pCTX, CertRec *pDBCert, void *pBody, BIN *pNewCert );
    int runCMP_CertConf( void *pCTX, UserRec *pDBUser, CertRec *pDBCert, void *pBody, BIN *pCert );

    int makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // CA_SERVER_H
