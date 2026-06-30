#include <QDebug>
#include <QtNetwork/QtNetwork>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>

#include "tsp_server.h"
#include "man_applet.h"
#include "commons.h"

#include "js_http.h"
#include "js_tsp.h"
#include "db_mgr.h"
#include "tsp_rec.h"
#include "audit_rec.h"

TSPServer::TSPServer( QObject *parent ) :
    QTcpServer(parent)
{
    log_edit_ = nullptr;
    p11_ = false;
    tls_ = false;

    memset( &tsp_cert_, 0x00, sizeof(BIN));
    memset( &tsp_pri_key_, 0x00, sizeof(BIN));
    memset( &tls_cert_, 0x00, sizeof(BIN));
    memset( &tls_pri_key_, 0x00, sizeof(BIN));

    client_ = nullptr;
    tls_client_ = nullptr;
}

TSPServer::~TSPServer()
{
    JS_BIN_reset( &tsp_cert_ );
    JS_BIN_reset( &tsp_pri_key_ );
    JS_BIN_reset( &tls_cert_ );
    JS_BIN_reset( &tls_pri_key_ );

    if( client_ ) delete client_;
    if( tls_client_ ) delete tls_client_;
}

void TSPServer::setLogEdit( QPlainTextEdit *pEdit )
{
    log_edit_ = pEdit;
}

void TSPServer::setTSPCert( const BIN *pCert )
{
    JS_BIN_reset( &tsp_cert_ );
    JS_BIN_copy( &tsp_cert_, pCert );
}

void TSPServer::setTSPPriKey( const BIN *pPriKey, bool bP11 )
{
    JS_BIN_reset( &tsp_pri_key_ );
    JS_BIN_copy( &tsp_pri_key_, pPriKey );
    p11_ = bP11;
}

void TSPServer::setTLS( const BIN *pCert, const BIN *pPriKey )
{
    tls_ = true;

    JS_BIN_reset( &tls_cert_ );
    JS_BIN_reset( &tls_pri_key_ );
    JS_BIN_copy( &tls_cert_, pCert );
    JS_BIN_copy( &tls_pri_key_, pPriKey );
}

void TSPServer::startServer( int nPort )
{
    if( !this->listen( QHostAddress::Any, nPort ) )
    {
        log( "Could not start server" );
    }
    else
    {
        log( QString( "Listening to port: %1" ).arg( nPort ) );
    }
}

static ASN1_INTEGER *serialCallback( void *data )
{
    ASN1_INTEGER *pASerial = NULL;
    DBMgr *dbMgr = (DBMgr *)data;

    int nSerial = dbMgr->getNextVal( "TB_SERIAL" );
    if( nSerial <= 0 )
    {
        fprintf( stderr, "fail to get serial value: %d", nSerial );
        return NULL;
    }


    fprintf( stderr, "Serial: %d", nSerial );
    pASerial = ASN1_INTEGER_new();

    ASN1_INTEGER_set( pASerial, nSerial );

    return pASerial;
}

int TSPServer::procTSP( const BIN *pReq, BIN *pRsp )
{
    int     ret = 0;
    BIN     binMsg = {0,0};
    BIN     binNonce = {0,0};
    char    sHash[1024];
    char    sPolicy[1024];
    //    const char *pPath = "D:/data/tsaserial";
    BIN     binTST = {0,0};
    BIN     binP7 = {0,0};
    int64_t nSerial = -1;
    TSPRec  tspRec;
    AuditRec auditRec;

    char *pHexTSTInfo = NULL;
    char *pHexData = NULL;

    DBMgr   *dbMgr = manApplet->dbMgr();

    memset( sPolicy, 0x00, sizeof(sPolicy));

    ret = JS_TSP_decodeRequest( pReq, &binMsg, sHash, sPolicy, &binNonce );
    if( ret != 0 )
    {
        log( QString( "fail to decode tsp request(%1)" ).arg( JERR(ret) ));
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );

        goto end;
    }

    //    if( g_nMsgDump ) msgDump( 1, pReq );

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

        ret = JS_TSP_encodeResponseByP11(
            pReq, sHash, sPolicy, &tsp_cert_, &tsp_pri_key_, pP11CTX,
            (void (*)(void *))serialCallback, (void *)dbMgr,
            &nSerial, &binTST, &binP7, pRsp );

        log( QString( "EncodeResponseByP11 Ret: %1" ).arg( JERR(ret) ));

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
    }
    else
    {
        ret = JS_TSP_encodeResponse(
            pReq, sHash, sPolicy, &tsp_cert_, &tsp_pri_key_,
            (void (*)(void *))serialCallback, dbMgr,
            &nSerial, &binTST, &binP7, pRsp );

        log( QString( "EncodeResponse Ret: %1" ).arg( JERR(ret) ) );
    }

    if( ret != 0 )
    {
        log( QString( "fail to encode tsp response(%1)" ).arg( JERR(ret) ) );
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );
        goto end;
    }
    else
    {
        //        if( g_nMsgDump ) msgDump( 0, pRsp );
    }

    JS_BIN_encodeHex( &binTST, &pHexTSTInfo );
    JS_BIN_encodeHex( &binP7, &pHexData );

    tspRec.setData( pHexData );
    tspRec.setRegTime( time(NULL ));
    tspRec.setSerial( nSerial );
    tspRec.setSrcHash( sHash );
    tspRec.setPolicy( sPolicy );
    tspRec.setTSTInfo( pHexTSTInfo );
    dbMgr->addTSPRec( tspRec );

    auditRec.setKind( JS_GEN_KIND_CERTMAN );
    auditRec.setOperation( JS_GEN_OP_MAKE_TSP );
    dbMgr->addAuditRec( auditRec );

    log( "TSP success" );

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binTST );
    JS_BIN_reset( &binP7 );

    if( pHexTSTInfo ) JS_free( pHexTSTInfo );
    if( pHexData ) JS_free( pHexData );

    return ret;
}

int TSPServer::readReady()
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
    else if( strcasecmp( pPath, "/TSP" ) == 0 )
    {
        QByteArray content = client_->readAll();
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content.length() ));
        JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

        log( QString( "Contents: %1" ).arg( getHexString(&binReq)));

        ret = procTSP( &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procTSP(%1)" ).arg(ret) );
            goto end;
        }

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "accept: application/tsp-response";
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "content-type: application/tsp-response";
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

int TSPServer::readTLSReady()
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
    else if( strcasecmp( pPath, "/TSP" ) == 0 )
    {
        QByteArray content = client_->readAll();
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content.length() ));
        JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

        log( QString( "Contents: %1" ).arg( getHexString(&binReq)));

        ret = procTSP( &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procTSP(%1)" ).arg(ret) );
            goto end;
        }

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "accept: application/tsp-response";
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "content-type: application/tsp-response";
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
    //    client_->waitForDisconnected();
    tls_client_->deleteLater();

    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );
    if( pPath ) JS_free( pPath );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    return ret;
}

void TSPServer::incomingConnection( qintptr  socketDescriptor )
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

        connect(tls_client_, &QSslSocket::readyRead, this, &TSPServer::readTLSReady );

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

        connect( client_, &QTcpSocket::readyRead, this, &TSPServer::readReady );
    }
}

void TSPServer::log( const QString strLog, QColor cr )
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

void TSPServer::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}
