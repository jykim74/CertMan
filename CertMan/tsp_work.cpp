#include "tsp_work.h"
#include <QtNetwork/QtNetwork>

#include "js_pki.h"
#include "commons.h"
#include "man_applet.h"
#include "settings_mgr.h"
#include "db_mgr.h"
#include "js_http.h"
#include "js_tsp.h"

TspWork::TspWork( qintptr ID, QObject *parent )
{
    this->socketDescriptor = ID;

    memset( &tsp_cert_, 0x00, sizeof(BIN));
    memset( &tsp_pri_key_, 0x00, sizeof(BIN));
}

TspWork::~TspWork()
{
    JS_BIN_reset( &tsp_cert_ );
    JS_BIN_reset( &tsp_pri_key_ );
}

void TspWork::setTSPCert( const BIN *pCert )
{
    JS_BIN_reset( &tsp_cert_ );
    JS_BIN_copy( &tsp_cert_, pCert );
}

void TspWork::setTSPPriKey( const BIN *pPriKey )
{
    JS_BIN_reset( &tsp_pri_key_ );
    JS_BIN_copy( &tsp_pri_key_, pPriKey );
}

void TspWork::run()
{
    qDebug() << "Thread started";

    socket = new QTcpSocket();

    if( !socket->setSocketDescriptor(this->socketDescriptor) )
    {
        elog( "setSocketDescriptor fail" );
        emit error( socket->error() );
        return;
    }

    connect( socket, SIGNAL(readyRead()), this, SLOT(readyRead()), Qt::DirectConnection );
    connect( socket, SIGNAL(disconnected()), this, SLOT(disconnected()) );

    qDebug() << socketDescriptor << " Client connected";

    exec();
}

#if 0
static ASN1_INTEGER* serialCallback( void *data )
{
    ASN1_INTEGER *pASerial = NULL;
    int nSerial = JS_DB_getNextVal( (sqlite3 *)data, "TB_SERIAL" );
    if( nSerial <= 0 )
    {
        LE( "fail to get serial value: %d", nSerial );
        return NULL;
    }

    LI( "Serial: %d", nSerial );
    pASerial = ASN1_INTEGER_new();

    ASN1_INTEGER_set( pASerial, nSerial );

    return pASerial;
}

int procTSP( sqlite3 *db, const BIN *pReq, BIN *pRsp )
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
    JDB_TSP sTSP;
    char *pHexTSTInfo = NULL;
    char *pHexData = NULL;

    memset( &sTSP, 0x00, sizeof(sTSP));
    memset( sPolicy, 0x00, sizeof(sPolicy));

    ret = JS_TSP_decodeRequest( pReq, &binMsg, sHash, sPolicy, &binNonce );
    if( ret != 0 )
    {
        LE( "fail to decode tsp request(%d)", ret );
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );

        goto end;
    }

    if( g_nMsgDump ) msgDump( 1, pReq );

    if( g_pP11CTX )
    {
        ret = JS_TSP_encodeResponseByP11(
            pReq, sHash, sPolicy, &g_binTspCert, &g_binTspPri, g_pP11CTX,
            (void *)serialCallback, (void *)db,
            &nSerial, &binTST, &binP7, pRsp );

        LI( "EncodeResponseByP11 Ret: %d", ret );
    }
    else
    {
        ret = JS_TSP_encodeResponse(
            pReq, sHash, sPolicy, &g_binTspCert, &g_binTspPri,
            (void *)serialCallback, (void *)db,
            &nSerial, &binTST, &binP7, pRsp );

        LI( "EncodeResponse Ret: %d", ret );
    }

    if( ret != 0 )
    {
        LE( "fail to encode tsp response(%d)", ret );
        ret = JS_TSP_encodeFailResponse( JS_TS_STATUS_REJECTION, pRsp );
        goto end;
    }
    else
    {
        if( g_nMsgDump ) msgDump( 0, pRsp );
    }

    JS_BIN_encodeHex( &binTST, &pHexTSTInfo );
    JS_BIN_encodeHex( &binP7, &pHexData );

    JS_DB_setTSP( &sTSP, -1, time(NULL), nSerial, sHash, sPolicy, pHexTSTInfo, pHexData );

    ret = JS_DB_addTSP( db, &sTSP );
    if( ret != 0 )
    {
        LE( "fail to add TSP to DB(%d)", ret );
        goto end;
    }

    JS_addAudit( db, JS_GEN_KIND_TSP_SRV, JS_GEN_OP_MAKE_TSP, NULL );
    LI( "TSP success" );

end :
    JS_BIN_reset( &binMsg );
    JS_BIN_reset( &binNonce );
    JS_BIN_reset( &binTST );
    JS_BIN_reset( &binP7 );
    JS_DB_resetTSP( &sTSP );
    if( pHexTSTInfo ) JS_free( pHexTSTInfo );
    if( pHexData ) JS_free( pHexData );

    return ret;
}
#endif

void TspWork::readyRead()
{
    int ret = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

#if 1
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;

    char            *pBody = NULL;

    const char      *pMethod = NULL;
    char            *pMethInfo = NULL;

    char            *pPath = NULL;
    int             nType = -1;

    ret = JS_HTTP_recvBin( (int)socketDescriptor, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        log( QString( "fail to receive message(%1)" ).arg( ret ));
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/TSP" ) == 0 )
    {
 //       ret = procTSP( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            log( QString( "fail procTSP(%1)" ).arg(ret) );
            goto end;
        }

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else
    {
        ret = -1;
        log( QString( "Invalid URL: %1" ).arg(pPath) );
        goto end;
    }

    JS_UTIL_createNameValList2("accept", "application/tsp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/tsp-response");

    ret = JS_HTTP_sendBin( (int)socketDescriptor, pMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        log( QString( "fail to send message(%1)" ).arg( ret ) );
        goto end;
    }

end :
    if( pBody ) JS_free( pBody );
    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );


    if( pMethInfo ) JS_free( pMethInfo );
    if( pPath ) JS_free( pPath );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

#else
    QByteArray Line;
    const QByteArray key = "Content-Length:";
    int nContentLength = 0;
    Line = socket->readLine();

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

        Line = socket->readLine();
        if( Line.length() <= 2 ) break;
    }

    QByteArray content = socket->readAll();

    log( QString( "Content Length: %1" ).arg( content.length() ));
    JS_BIN_set( &binReq, (const unsigned char *)content.data(), content.length() );

    log( QString( "Contents: %1" ).arg( getHexString(&binReq)));


    socket->write( content );
    socket->flush();
    socket->disconnectFromHost();
    socket->waitForDisconnected();

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
#endif
}

void TspWork::disconnected()
{
    log( QString( QString( "Disconnected: %1" ).arg( socketDescriptor )));

    socket->deleteLater();
    exit(0);
}

void TspWork::log( const QString strLog, QColor cr )
{
    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;
    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );
    qDebug() << strMsg;
}

void TspWork::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}
