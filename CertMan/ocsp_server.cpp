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

    if( client_ )
    {
        client_->deleteLater();
        client_ = nullptr;
    }

    if( tls_client_ )
    {
        tls_client_->deleteLater();
        tls_client_ = nullptr;
    }

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

int OCSPServer::startServer( int nPort )
{
    if( !this->listen( QHostAddress::Any, nPort) )
    {
        log( "Could not start server" );
        return JSR_ERR;
    }
    else
    {
        if( tls_ == true )
            log( QString( "TLS Listening to port: %1" ).arg( nPort ));
        else
            log( QString( "Listening to port: %1" ).arg( nPort ));

        return JSR_OK;
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

    const char      *pMethod = NULL;

    headers_.clear();
    content_len_ = 0;

    QByteArray Line;
    Line = client_->readLine();

    QList<QByteArray> first = Line.split( ' ' );
    if( first.size() >= 3 )
    {
        method_ = first[0];
        path_ = first[1];
        version_ = first[2];
    }

    while( 1 )
    {
        Line = client_->readLine();
        log( QString( "Line: %1" ).arg( Line.data() ));

        if( Line.length() <= 2 ) break;

        QByteArray l = Line.trimmed();
        int pos = l.indexOf( ':' );

        if( pos < 0 ) continue;

        QString key = QString::fromUtf8( l.left(pos) ).trimmed();
        QString value = QString::fromUtf8( l.mid(pos+1)).trimmed();

        headers_[key] = value;

        if( key.compare( "Content-Length", Qt::CaseInsensitive ) == 0 )
        {
            content_len_ = value.toInt();
        }
    }

    if( content_len_ > 0 )
    {
        body_ = client_->readAll();
    }

    if( path_.compare( "/PING", Qt::CaseInsensitive ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( path_.compare( "/OCSP", Qt::CaseInsensitive ) == 0 )
    {
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content_len_ ));
        JS_BIN_set( &binReq, (const unsigned char *)body_.data(), content_len_ );

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

        if( binRsp.nLen > 0 )
        {
            rsp.setRawData( (const char *)binRsp.pVal, binRsp.nLen );
            client_->write( "\r\n" );
            client_->write( rsp );
        }

        client_->flush();
    }
    else
    {
        ret = -1;
        log( QString( "Invalid URL: %1" ).arg( path_ ) );
        goto end;
    }


end :
    client_->disconnectFromHost();
    client_->deleteLater();

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    resetState();
    return ret;
}

void OCSPServer::onEncrypted()
{
    QSslSocket *socket = qobject_cast<QSslSocket *>(sender());

    qDebug() << "TLS Connected";
}

void OCSPServer::onTLSReadyRead()
{
    buffer_ += tls_client_->readAll();

    processBuffer();
}

void OCSPServer::onTLSDisconnected()
{
    resetState();
}

void OCSPServer::incomingConnection( qintptr  socketDescriptor )
{
    log( "Connecting..." );

    if( tls_ == true )
    {
        if( QSslSocket::supportsSsl() == false )
        {
            elog( "TLS is not supported." );
            return;
        }

        tls_client_ = new QSslSocket(this);

        if (!tls_client_->setSocketDescriptor(socketDescriptor))
        {
            delete tls_client_;
            return;
        }

        int nKeyType = JS_PKI_getCertKeyType( &tls_cert_ );
        int nPriType = -1;
        if( nKeyType == JS_PKI_KEY_TYPE_RSA )
            nPriType = QSsl::Rsa;
        else if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
            nPriType = QSsl::Ec;
        else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
            nPriType = QSsl::Dsa;
        else
        {
            elog( QString( "Invalid TLS KeyAlgorithm: %1").arg( nKeyType ));
            return;
        }

        QByteArray der_cert = QByteArray( (const char *)tls_cert_.pVal, tls_cert_.nLen );
        QSslCertificate cert( der_cert, QSsl::Der );

        QByteArray der_key = QByteArray( (const char *)tls_pri_key_.pVal, tls_pri_key_.nLen );
        QSslKey key( der_key, (QSsl::KeyAlgorithm)nPriType, QSsl::Der );

        tls_client_->setLocalCertificate(cert);
        tls_client_->setPrivateKey(key);
        tls_client_->setPeerVerifyMode(QSslSocket::VerifyNone);

        connect(tls_client_, SIGNAL(encrypted()), this, SLOT(onEncrypted()));
        connect(tls_client_, &QSslSocket::readyRead, this, &OCSPServer::onTLSReadyRead);
        connect(tls_client_, &QSslSocket::disconnected, this, &OCSPServer::onTLSDisconnected);

        tls_client_->startServerEncryption();
    }
    else
    {
        client_ = new QTcpSocket;
        client_->setSocketDescriptor( socketDescriptor );

        connect( client_, &QTcpSocket::readyRead, this, &OCSPServer::readReady );
    }
}

void OCSPServer::processBuffer()
{
    while( 1 )
    {
        if( state_ == WaitingHeader )
        {
            int pos = buffer_.indexOf( "\r\n\r\n" );
            if( pos < 0 ) return;

            QByteArray header = buffer_.left(pos);

            parseHeader( header );

            buffer_.remove(0, pos+4);
            if( content_len_ == 0 )
            {
                processOCSP();
                continue;
            }

            state_ = WaitingBody;
        }

        if( state_ == WaitingBody )
        {
            if( buffer_.size() < content_len_ )
                return;

            body_ = buffer_.left( content_len_ );
            buffer_.remove( 0, content_len_ );
            processOCSP();
        }
    }
}

void OCSPServer::parseHeader(const QByteArray &header)
{
    headers_.clear();
    content_len_ = 0;

    QList<QByteArray> lines = header.split( '\n' );

    if( lines.isEmpty() ) return;

    QByteArray requestLine = lines.takeFirst().trimmed();
    QList<QByteArray> first = requestLine.split(' ');

    if( first.size() >= 3 )
    {
        method_ = first[0];
        path_ = first[1];
        version_ = first[2];
    }

    for( const QByteArray &line : lines )
    {
        QByteArray l = line.trimmed();
        int pos = l.indexOf( ':' );

        if( pos < 0 ) continue;

        QString key = QString::fromUtf8( l.left(pos) ).trimmed();
        QString value = QString::fromUtf8( l.mid(pos+1)).trimmed();

        headers_[key] = value;

        if( key.compare( "Content-Length", Qt::CaseInsensitive ) == 0 )
        {
            content_len_ = value.toInt();
        }
    }
}

void OCSPServer::resetState()
{
    state_ = WaitingHeader;
    content_len_ = 0;
    headers_.clear();
    body_.clear();
    method_.clear();
    path_.clear();
    version_.clear();
}

void OCSPServer::processOCSP()
{
    int ret = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    const char      *pMethod = NULL;

    if( strcasecmp( path_.toStdString().c_str(), "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( path_.toStdString().c_str(), "/OCSP" ) == 0 )
    {
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content_len_ ));
        JS_BIN_set( &binReq, (const unsigned char *)body_.data(), content_len_ );

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

        if( binRsp.nLen > 0 )
        {
            rsp.setRawData( (const char *)binRsp.pVal, binRsp.nLen );
            tls_client_->write( "\r\n" );
            tls_client_->write( rsp );
        }

        tls_client_->flush();
    }
    else
    {
        ret = -1;
        log( QString( "Invalid URL: %1" ).arg( path_ ) );
        goto end;
    }


end :
    tls_client_->disconnectFromHost();
    tls_client_->deleteLater();

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    resetState();
}
