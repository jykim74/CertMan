#include <QDebug>
#include <QtNetwork/QtNetwork>
#include "ocsp_server.h"
#include "man_applet.h"
#include "commons.h"

#include "js_http.h"
#include "js_cmp.h"
#include "js_cmp_srv.h"
#include "db_mgr.h"
#include "audit_rec.h"
#include "signer_rec.h"

#include "ca_server.h"

CAServer::CAServer( QObject *parent ) :
    QTcpServer(parent)
{
    log_edit_ = nullptr;

    memset( &ca_cert_, 0x00, sizeof(BIN));
    memset( &ca_pri_key_, 0x00, sizeof(BIN));
}

CAServer::~CAServer()
{
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_reset( &ca_pri_key_ );

    if( client_ ) delete client_;
}

void CAServer::setLogEdit( QPlainTextEdit *pEdit )
{
    log_edit_ = pEdit;
}

void CAServer::setCACert( const BIN *pCert )
{
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_copy( &ca_cert_, pCert );
}

void CAServer::setCAPriKey( const BIN *pPriKey )
{
    JS_BIN_reset( &ca_pri_key_ );
    JS_BIN_copy( &ca_pri_key_, pPriKey );
}

void CAServer::startServer( int nPort )
{
    if( !this->listen( QHostAddress::Any, nPort) )
    {
        qDebug() << "Could not start server";
    }
    else
    {
        qDebug() << "Listening to port " << nPort << "...";
    }
}

void CAServer::log( const QString strLog, QColor cr )
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

void CAServer::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

int CAServer::procCMP( const BIN *pReq, BIN *pRsp )
{
    return 0;
}

int CAServer::workPKIOperation( const BIN *pPKIReq, BIN *pCertRsp )
{
    return 0;
}

int CAServer::procSCEP( const JNameValList *pParamList, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    const char *pOper = NULL;
    JS_UTIL_printNameValList( stdout, "ParamList", pParamList );

    pOper = JS_UTIL_valueFromNameValList( pParamList, "operation" );

    if( pOper == NULL )
    {
        log( "There is no operation" );
        return -1;
    }

    log( "SCEP Operation: %s", pOper );

    if( strcasecmp( pOper, "GetCACaps") == 0 )
    {
        const char *pMsg = "POSTPKIOperation\r\nRenewal\r\nSHA-1";
        JS_BIN_set( pRsp, (const unsigned char *)pMsg, strlen( pMsg ) );
    }
    else if( strcasecmp( pOper, "GetCACert" ) == 0 )
    {
        if( ca_cert_.nLen <= 0 )
        {
            log( "CA certificate is empty" );
        }
        else
        {
            JS_BIN_copy( pRsp, &ca_cert_ );
        }
    }
    else if( strcasecmp( pOper, "PKIOperation" ) == 0 )
    {
        ret = workPKIOperation( pReq, pRsp );
    }
    else
    {
        log( "invalid operation : %s", pOper );
        return -1;
    }

    return ret;
}

int CAServer::readReady()
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
    else if( strcasecmp( pPath, "/CMP" ) == 0 )
    {
        QByteArray content = client_->readAll();
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content.length() ));
        JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

        log( QString( "Contents: %1" ).arg( getHexString(&binReq)));

        ret = procCMP( &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procCMP(%1)" ).arg(ret) );
            goto end;
        }

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "accept: application/cmp-response";
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "content-type: application/cmp-response";
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
    else if( strcasecmp( pPath, "/pkiclient.exe" ) == 0 )
    {
        QByteArray content = client_->readAll();
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content.length() ));
        JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

        log( QString( "Contents: %1" ).arg( getHexString(&binReq)));

        ret = procSCEP( pParamList, &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procSCEP(%1)" ).arg(ret) );
            goto end;
        }

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "accept: application/scep-response";
        rsp += "\r\n";
        client_->write( rsp );

        rsp = "content-type: application/scep-response";
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
    client_->waitForDisconnected();
    delete client_;
    client_ = nullptr;

    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );
    if( pPath ) JS_free( pPath );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void CAServer::incomingConnection( qintptr  socketDescriptor )
{
    log( "Connecting..." );

    if( client_ == nullptr ) delete client_;

    client_ = new QTcpSocket;
    client_->setSocketDescriptor( socketDescriptor );

    connect( client_, &QTcpSocket::readyRead, this, &CAServer::readReady );
}
