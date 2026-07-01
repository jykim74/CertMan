#include <QDebug>
#include <QtNetwork/QtNetwork>
#include "ocsp_server.h"
#include "man_applet.h"
#include "commons.h"

#include "js_http.h"
#include "js_ocsp.h"
#include "db_mgr.h"
#include "audit_rec.h"
#include "signer_rec.h"
#include "commons.h"

OCSPServer::OCSPServer( QObject *parent ) :
    QTcpServer(parent)
{
    log_edit_ = nullptr;
    need_sign_ = false;
    p11_ = false;
    tls_ = false;

    client_ = nullptr;
    tls_client_ = nullptr;

    memset( &ca_cert_, 0x00, sizeof(BIN));
    memset( &ocsp_cert_, 0x00, sizeof(BIN));
    memset( &ocsp_pri_key_, 0x00, sizeof(BIN));
    memset( &tls_cert_, 0x00, sizeof(BIN));
    memset( &tls_pri_key_, 0x00, sizeof(BIN));
}

OCSPServer::~OCSPServer()
{
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_reset( &ocsp_cert_ );
    JS_BIN_reset( &ocsp_pri_key_ );
    JS_BIN_reset( &tls_cert_ );
    JS_BIN_reset( &tls_pri_key_ );

    if( client_ ) delete client_;
    if( tls_client_ ) delete tls_client_;

    log( "OCSP server stopped" );
}

void OCSPServer::setLogEdit( QPlainTextEdit *pEdit )
{
    log_edit_ = pEdit;
}

void OCSPServer::setCACert( const BIN *pCert )
{
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_copy( &ca_cert_, pCert );
}

void OCSPServer::setOCSPCert( const BIN *pCert )
{
    JS_BIN_reset( &ocsp_cert_ );
    JS_BIN_copy( &ocsp_cert_, pCert );
}

void OCSPServer::setOCSPPriKey( const BIN *pPriKey, bool bP11 )
{
    JS_BIN_reset( &ocsp_pri_key_ );
    JS_BIN_copy( &ocsp_pri_key_, pPriKey );
    p11_ = bP11;
}

void OCSPServer::setTLS( const BIN *pCert, const BIN *pPriKey )
{
    tls_ = true;

    JS_BIN_reset( &tls_cert_ );
    JS_BIN_reset( &tls_pri_key_ );
    JS_BIN_copy( &tls_cert_, pCert );
    JS_BIN_copy( &tls_pri_key_, pPriKey );
}

void OCSPServer::setNeedSign( bool bVal )
{

}

void OCSPServer::startServer( int nPort )
{
    if( !this->listen( QHostAddress::Any, nPort) )
    {
        log( "Could not start server" );
    }
    else
    {
        log( QString( "Listening to port: %1" ).arg( nPort ) );
    }
}

void OCSPServer::log( const QString strLog, QColor cr )
{
    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;
    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );

    if( log_edit_ )
    {
        QTextCursor cursor = log_edit_->textCursor();

        QTextCharFormat format;
        format.setForeground( cr );
        cursor.mergeCharFormat(format);


        cursor.insertText( strMsg );

        log_edit_->setTextCursor( cursor );
        log_edit_->repaint();
    }
    else
    {
        qDebug() << strMsg;
    }
}

void OCSPServer::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

int OCSPServer::getCertStatus( JCertIDInfo *pIDInfo, JCertStatusInfo *pStatusInfo )
{
    int     ret = 0;

    int             nStatus = JS_OCSP_CERT_STATUS_GOOD;
    int             nReason = 0;
    time_t             tRevokedTime = 0;

    DBMgr* dbMgr = manApplet->dbMgr();
    CertRec certRec;
//    CertRec issuerRec;
    RevokeRec revokeRec;
    AuditRec auditRec;

    BIN binCA_KeyHash = {0,0};
    BIN binCA_DNHash = {0,0};

    BIN binKeyHash = {0,0};
    BIN binDNHash = {0,0};

    log( QString( "Hash: %1").arg( pIDInfo->pHash ));
    log( QString( "KeyHash: %1").arg( pIDInfo->pKeyHash ));
    log( QString( "DNHash: %1" ).arg( pIDInfo->pNameHash ));
    log( QString( "Serial: %1" ).arg( pIDInfo->pSerial ));

    JS_BIN_decodeHex( pIDInfo->pKeyHash, &binKeyHash );
    JS_BIN_decodeHex( pIDInfo->pNameHash, &binDNHash );
/*
    ret = dbMgr->getCertRecByKeyHash( pIDInfo->pKeyHash, issuerRec );
    if( ret != JSR_OK )
    {
        log( QString("fail to get Issuer by KeyHash(%1)").arg( pIDInfo->pKeyHash ));
        nStatus = JS_OCSP_CERT_STATUS_UNKNOWN;
        ret = JSR_OK;
        goto end;
    }
*/
    ret = JS_PKI_getKeyDNHash( &ca_cert_, pIDInfo->pHash, &binCA_KeyHash, &binCA_DNHash );
    if( ret != JSR_OK )
    {
        ret = JSR_SYSTEM_FAIL;
        goto end;
    }

    if( JS_BIN_cmp( &binCA_KeyHash, &binKeyHash ) != 0 )
    {
        log( QString("KeyHash is mismatched(%1)").arg( pIDInfo->pKeyHash ));
        nStatus = JS_OCSP_CERT_STATUS_UNKNOWN;
        ret = JSR_OK;
        goto end;
    }

    if( JS_BIN_cmp( &binCA_DNHash, &binDNHash ) != 0 )
    {
        log( QString("DNHash is mismatched(%1)").arg( pIDInfo->pKeyHash ));
        nStatus = JS_OCSP_CERT_STATUS_UNKNOWN;
        ret = JSR_OK;
        goto end;
    }

    /* Need To check Issuer DN Hash too */

    ret = dbMgr->getCertRecBySerial( pIDInfo->pSerial, certRec );
    if( ret != JSR_OK )
    {
        log( QString("fail to get cert by serial(%1)").arg( pIDInfo->pSerial ));
        nStatus = JS_OCSP_CERT_STATUS_UNKNOWN;
        ret = JSR_OK;
        goto end;
    }

    ret = dbMgr->getRevokeRecByCertNum( certRec.getNum(), revokeRec );
    if( ret == JSR_OK )
    {
        nStatus = JS_OCSP_CERT_STATUS_REVOKED;
        nReason = revokeRec.getReason();
        tRevokedTime = revokeRec.getRevokeDate();

        log( QString("The cert is revoked[Num:%1 Reason:%2 RevokedTime:%3]").arg(certRec.getNum()).arg(nReason).arg(tRevokedTime));
    }
    else
    {
        log( QString("The cert is good[Num:%1]").arg( certRec.getNum() ) );
        ret = JSR_OK;
    }

    auditRec.setKind( JS_GEN_KIND_CERTMAN );
    auditRec.setOperation( JS_GEN_OP_CHECK_OCSP );
    dbMgr->addAuditRec( auditRec );
    JS_OCSP_setCertStatusInfo( pStatusInfo, nStatus, nReason, tRevokedTime, NULL );

end :
    JS_BIN_reset( &binCA_KeyHash );
    JS_BIN_reset( &binCA_DNHash );
    JS_BIN_reset( &binKeyHash );
    JS_BIN_reset( &binDNHash );

    return ret;
}

int OCSPServer::procOCSP( const BIN *pReq, BIN *pRsp )
{
    int     ret = 0;

    JCertIDInfo    sIDInfo;
    JCertStatusInfo sStatusInfo;

    char *pSignerName = NULL;
    char *pDNHash = NULL;

    BIN binSigner = {0,0};
    DBMgr* dbMgr = manApplet->dbMgr();

    SignerRec signerRec;

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));

    if( need_sign_ == true )
    {
        ret = JS_OCSP_getReqSignerName( pReq, &pSignerName, &pDNHash );
        if( ret != 0 )
        {
            log( QString("Request need to sign(%1)").arg(ret) );
            ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_SIGREQUIRED, pRsp );
            goto end;
        }

        log( QString("Request is Signed( SignerName : %1)").arg( pSignerName ) );
        ret = dbMgr->getSignerRecByDNHash( SIGNER_TYPE_OCSP, pDNHash, signerRec );

        if( ret != JSR_OK )
        {
            log( QString("There is no signer cert[%1]").arg( pSignerName ));
            ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_UNAUTHORIZED, pRsp );
            goto end;
        }

        if( signerRec.getStatus() != 1 )
        {
            log( QString("The signer is not valid[%1]").arg( signerRec.getStatus() ));
            ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_UNAUTHORIZED, pRsp );
            goto end;
        }

        JS_BIN_decodeHex( signerRec.getCert().toStdString().c_str(), &binSigner );
    }


    ret = JS_OCSP_decodeRequest( pReq, &binSigner, &sIDInfo );
    if( ret != 0 )
    {
        log( QString( "fail to decode request(%1)").arg(JERR(ret) ));
        ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, pRsp );
        goto end;
    }

    ret = getCertStatus( &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        log( QString( "fail to get cert status(%1)").arg( JERR(ret) ));
        ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_INTERNALERROR, pRsp );
        goto end;
    }

    if( p11_ == true )
    {
        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        if( pP11CTX == NULL )
        {
            log( QString("PKCS11 library was not loaded") );
            ret = -1;
            goto end;
        }

        ret = getP11Session( pP11CTX, nSlotID, strPIN );
        if( ret != 0 )
        {
            log( QString( "Failed to fetch session: %1 ").arg( JERR(ret) ));
            JS_PKCS11_Logout( pP11CTX );
            JS_PKCS11_CloseSession( pP11CTX );
            ret = -1;
            goto end;
        }

        ret = JS_OCSP_encodeResponseByP11( pReq, &ocsp_cert_, &ocsp_pri_key_, pP11CTX, "SHA1", &sIDInfo, &sStatusInfo, pRsp );
        log( QString( "EncodeResponsByP11 Ret: %1").arg( JERR(ret) ));

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
    }
    else
    {
        ret = JS_OCSP_encodeResponse( pReq, &ocsp_cert_, &ocsp_pri_key_, "SHA1", &sIDInfo, &sStatusInfo, pRsp );
        log( QString( "EncodeResponse Ret: %1").arg( JERR(ret) ));
    }

    if( ret != 0 )
    {
//        log( QString( "fail to encode OCSP response message(%1)").arg( ret ));
        ret = JS_OCSP_encodeFailResponse( JS_OCSP_RESPONSE_STATUS_INTERNALERROR, pRsp );
        goto end;
    }

end :

    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
    if( pSignerName ) JS_free( pSignerName );
    if( pDNHash ) JS_free( pDNHash );
    JS_BIN_reset( &binSigner );

    return ret;
}

int OCSPServer::readReady()
{
    int ret = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    JNameValList    *pParamList = NULL;

    char            *pPath = NULL;
    int             nType = -1;
    const char      *pMethod = NULL;

    QByteArray Line;
    const QByteArray key = "Content-Length:";
    int nContentLength = 0;
    Line = client_->readLine();

    JS_HTTP_getMethodPath( Line.data(), &nType, &pPath, &pParamList );
    if( pPath == NULL ) return JSR_HTTP_BAD_PATH;

    while( Line.length() > 0 )
    {
        log( QString( "Line: %1" ).arg( Line.data() ));

        int pos = Line.indexOf( key );
        if( pos >= 0 )
        {
            QByteArray value = Line.mid( pos + key.length(), Line.length() - pos ).trimmed();
            nContentLength = value.toLongLong();
            log( QString( "Content-Length: %1" ).arg( nContentLength ));
        }

        Line = client_->readLine();
        if( Line.length() <= 2 ) break;
    }

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/OCSP" ) == 0 )
    {
        QByteArray content = client_->readAll();
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content.length() ));
        JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

        log( QString( "Contents: %1" ).arg( getHexString(&binReq)));

        ret = procOCSP( &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procOCSP(%1)" ).arg(ret) );
            goto end;
        }

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "accept: application/ocsp-response";
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "content-type: application/ocsp-response";
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "Content-Length: ";
        rsp += strLen;
        rsp += "\r\n";
        client_->write( rsp );

        rsp.setRawData( (const char *)binRsp.pVal, binRsp.nLen );

        client_->write( "\r\n" );
        client_->write( rsp );
        client_->flush();
    }
    else
    {
        ret = -1;
        log( QString( "Invalid URL: %1" ).arg(pPath) );
        goto end;
    }


end :
    client_->disconnectFromHost();
//    client_->waitForDisconnected();
    client_->deleteLater();

    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );
    if( pPath ) JS_free( pPath );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    return ret;
}

int OCSPServer::readTLSReady()
{
    int ret = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    JNameValList    *pParamList = NULL;

    char            *pPath = NULL;
    int             nType = -1;
    const char      *pMethod = NULL;

    QByteArray Line;
    const QByteArray key = "Content-Length:";
    int nContentLength = 0;
    Line = tls_client_->readLine();

    JS_HTTP_getMethodPath( Line.data(), &nType, &pPath, &pParamList );
    if( pPath == NULL ) return JSR_HTTP_BAD_PATH;

    while( Line.length() > 0 )
    {
        log( QString( "Line: %1" ).arg( Line.data() ));

        int pos = Line.indexOf( key );
        if( pos >= 0 )
        {
            QByteArray value = Line.mid( pos + key.length(), Line.length() - pos ).trimmed();
            nContentLength = value.toLongLong();
            log( QString( "Content-Length: %1" ).arg( nContentLength ));
        }

        Line = tls_client_->readLine();
        if( Line.length() <= 2 ) break;
    }

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/OCSP" ) == 0 )
    {
        QByteArray content = tls_client_->readAll();
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content.length() ));
        JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

        log( QString( "Contents: %1" ).arg( getHexString(&binReq)));

        ret = procOCSP( &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procOCSP(%1)" ).arg(ret) );
            goto end;
        }

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "accept: application/ocsp-response";
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "content-type: application/ocsp-response";
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "Content-Length: ";
        rsp += strLen;
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp.setRawData( (const char *)binRsp.pVal, binRsp.nLen );

        tls_client_->write( "\r\n" );
        tls_client_->write( rsp );
        tls_client_->flush();
    }
    else
    {
        ret = -1;
        log( QString( "Invalid URL: %1" ).arg(pPath) );
        goto end;
    }


end :
    tls_client_->disconnectFromHost();
    tls_client_->deleteLater();

    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );
    if( pPath ) JS_free( pPath );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    return ret;
}


void OCSPServer::incomingConnection( qintptr  socketDescriptor )
{
    log( "Connecting..." );

    if( tls_ == true )
    {
        tls_client_ = new QSslSocket(this);

        if (!tls_client_->setSocketDescriptor(socketDescriptor))
        {
            delete tls_client_;
            return;
        }

        // 서버 인증서
        QFile certFile("server.crt");
        certFile.open(QIODevice::ReadOnly);

        QSslCertificate cert(&certFile, QSsl::Pem);
        // 개인키
        QFile keyFile("server.key");
        keyFile.open(QIODevice::ReadOnly);

        QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem);

        tls_client_->setLocalCertificate(cert);
        tls_client_->setPrivateKey(key);

        connect(tls_client_, &QSslSocket::encrypted,
                []()
                {
                    qDebug() << "TLS Connected";
                });

        connect(tls_client_, &QSslSocket::readyRead, this, &OCSPServer::readTLSReady );

        connect(tls_client_,
                QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors),
                [](const QList<QSslError> &errors)
                {
                    for (const auto &e : errors)
                        qDebug() << e.errorString();
                });

        tls_client_->startServerEncryption();
    }
    else
    {
        client_ = new QTcpSocket;
        client_->setSocketDescriptor( socketDescriptor );

        connect( client_, &QTcpSocket::readyRead, this, &OCSPServer::readReady );
    }
}
