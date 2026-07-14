#include <QDebug>
#include <QtNetwork/QtNetwork>


#include "ocsp_server.h"
#include "man_applet.h"
#include "commons.h"

#include "js_http.h"
#include "js_cmp.h"
#include "js_cmp_srv.h"
#include "js_pkcs7.h"
#include "js_pki_ext.h"
#include "js_pki_tools.h"
#include "js_cmp_srv.h"
#include "js_pkcs11.h"

#include "db_mgr.h"
#include "audit_rec.h"
#include "signer_rec.h"
#include "user_rec.h"
#include "commons.h"

#include "acme_object.h"
#include "acme_server.h"
#include "acme_stat.h"

ACMEServer::ACMEServer( QObject *parent ) :
    QTcpServer(parent)
{
    log_edit_ = nullptr;
    ca_num_ = -1;
    port_ = -1;
    p11_ = false;
    tls_ = false;

    client_ = nullptr;
    tls_client_ = nullptr;

    param_list_ = nullptr;

    memset( &ca_cert_, 0x00, sizeof(BIN));
    memset( &ca_pri_key_, 0x00, sizeof(BIN));
    memset( &tls_cert_, 0x00, sizeof(BIN));
    memset( &tls_pri_key_, 0x00, sizeof(BIN));
}

ACMEServer::~ACMEServer()
{
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_reset( &ca_pri_key_ );
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

    acme_stats_.clear();

    resetState();

    log( "ACME server stopped" );
}

void ACMEServer::setLogEdit( QPlainTextEdit *pEdit )
{
    log_edit_ = pEdit;
}

void ACMEServer::setCACert( const BIN *pCert )
{
    JS_BIN_reset( &ca_cert_ );
    JS_BIN_copy( &ca_cert_, pCert );
}

void ACMEServer::setCANum( int nNum )
{
    ca_num_ = nNum;
}

void ACMEServer::setProfileNum( int nNum )
{
    profile_num_ = nNum;
}

void ACMEServer::setCAPriKey( const BIN *pPriKey, bool bP11 )
{
    JS_BIN_reset( &ca_pri_key_ );
    JS_BIN_copy( &ca_pri_key_, pPriKey );
    p11_ = bP11;
}

void ACMEServer::setTLS( const BIN *pCert, const BIN *pPriKey )
{
    tls_ = true;

    JS_BIN_reset( &tls_cert_ );
    JS_BIN_reset( &tls_pri_key_ );
    JS_BIN_copy( &tls_cert_, pCert );
    JS_BIN_copy( &tls_pri_key_, pPriKey );
}

int ACMEServer::startServer( int nPort )
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

        port_ = nPort;

        return JSR_OK;
    }
}

void ACMEServer::log( const QString strLog, QColor cr )
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

void ACMEServer::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

int ACMEServer::makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert )
{
    int ret = 0;

    DBMgr* dbMgr = manApplet->dbMgr();

    JExtensionInfoList  *pExtInfoList = NULL;
    CertProfileRec profileRec;
    QList<ProfileExtRec> profileExtList;

    dbMgr->getCertProfileRec( profile_num_, profileRec );
    dbMgr->getCertProfileExtensionList( profile_num_, profileExtList );

    for( int i = 0; i < profileExtList.size(); i++ )
    {
        JExtensionInfo sExtInfo;
        ProfileExtRec profileExt = profileExtList.at(i);

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        if( profileExt.getSN() == JS_PKI_ExtNameSKI )
        {
            BIN binPub = {0,0};
            BIN binPubKeyID = {0,0};

            JS_BIN_decodeHex(pIssueCertInfo->pPublicKey, &binPub);
            ret = JS_PKI_getKeyIdentifier( &binPub, &binPubKeyID );
            if( ret != 0 )
            {
                log( QString( "fail to get KeyIdentifier: %1").arg( ret ) );
                goto end;
            }

            profileExt.setValue( getHexString( &binPubKeyID ));
            JS_BIN_reset( &binPubKeyID );
        }
        else if( profileExt.getSN() == JS_PKI_ExtNameAKI )
        {
            char    sHexID[128];
            char    sHexSerial[128];
            char    sHexIssuer[1024];

            char    sBuf[2048];

            memset( sHexID, 0x00, sizeof(sHexID));
            memset( sHexSerial, 0x00, sizeof(sHexSerial));
            memset( sHexIssuer, 0x00, sizeof(sHexIssuer));
            memset( sBuf, 0x00, sizeof(sBuf));

            ret = JS_PKI_getAuthorityKeyIdentifier( &ca_cert_, sHexID, sHexSerial, sHexIssuer );
            if( ret != 0 )
            {
                log( QString( "fail to get AuthorityKeyIdentifier: %1").arg( ret ));
                goto end;
            }

            sprintf( sBuf, "KEYID$%s#ISSUER$%s#SERIAL$%s", sHexID, sHexIssuer, sHexSerial );
            profileExt.setValue( sBuf );
        }

        ret = transExtInfoFromDBRec( &sExtInfo, profileExt );
        if( ret == 0 )
            JS_PKI_addExtensionInfoList( &pExtInfoList, &sExtInfo );
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

        ret = JS_PKI_makeCertificateByP11( 0, pIssueCertInfo, pExtInfoList, &ca_pri_key_, &ca_cert_, pP11CTX, pCert );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
    }
    else
    {
        ret = JS_PKI_makeCertificate( 0, pIssueCertInfo, pExtInfoList, &ca_pri_key_, &ca_cert_, pCert );
    }

end :
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return ret;
}

int ACMEServer::issueCert( const BIN *pCSR, BIN *pCert )
{
    int ret = 0;

    DBMgr* dbMgr = manApplet->dbMgr();

    CertProfileRec profileRec;
    QList<ProfileExtRec> profileExtList;
    CertRec certRec;

    JCertInfo   sNewCertInfo;

    dbMgr->getCertProfileRec( profile_num_, profileRec );
    dbMgr->getCertProfileExtensionList( profile_num_, profileExtList );

    time_t now_t = time(NULL);
    time_t notBefore = 0;
    time_t notAfter = 0;

    JReqInfo sReqInfo;
    char        sSerial[64];
    JIssueCertInfo sIssueCertInfo;
    int nSeq = -1;
    int nKeyType = -1;
    BIN binNewCert ={0,0};
    char        *pHexCert = NULL;
    BIN binPub = {0,0};
    BIN binKeyID = {0,0};

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));
    memset( sSerial, 0x00, sizeof(sSerial));
    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));

    JS_PKI_getPeriod( profileRec.getNotBefore(),
                     profileRec.getNotAfter(),
                     now_t,
                     &notBefore,
                     &notAfter );

    ret = JS_PKI_getReqInfo( pCSR, &sReqInfo, 1, NULL );
    if( ret != 0 )
    {
        log( QString( "fail to parse request : %1" ).arg(ret ));
        goto end;
    }

    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
    nKeyType = JS_PKI_getPubKeyType( &binPub );
    JS_PKI_getKeyIdentifier( &binPub, &binKeyID );

    nSeq = dbMgr->getNextVal( "TB_CERT" );
    sprintf( sSerial, "%d", nSeq );

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                            profileRec.getVersion(),
                            sSerial,
                            profileRec.getHash().toStdString().c_str(),
                            sReqInfo.pSubjectDN,
                            notBefore,
                            notAfter,
                            nKeyType,
                            sReqInfo.pPublicKey );

    ret = makeCert( &sIssueCertInfo, &binNewCert );

    if( ret != 0 )
    {
        log( QString( "fail to make certificate : %1").arg( ret ) );
        goto end;
    }

    JS_BIN_encodeHex( &binNewCert, &pHexCert );

    ret = JS_PKI_getCertInfo( &binNewCert, &sNewCertInfo, NULL );
    if( ret != 0 )
    {
        log( QString( "fail to get certificate information: %1" ).arg( ret ));
        goto end;
    }

    certRec.setRegTime( now_t );
    certRec.setNotBefore( notBefore );
    certRec.setNotAfter( notAfter );
    certRec.setSignAlg( sNewCertInfo.pSignAlgorithm );
    certRec.setCert( getHexString( &binNewCert ));
    certRec.setIssuerNum( ca_num_ );
    certRec.setSubjectDN( sNewCertInfo.pSubjectName );
    certRec.setSerial( sNewCertInfo.pSerial );
    certRec.setDNHash( sNewCertInfo.pDNHash );
    certRec.setKeyHash( getHexString( &binKeyID) );

    dbMgr->addCertRec( certRec );
    JS_BIN_copy( pCert, &binNewCert );

end :
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_PKI_resetReqInfo( &sReqInfo );
    JS_BIN_reset( &binNewCert );
    JS_PKI_resetCertInfo( &sNewCertInfo );
    if( pHexCert ) JS_free( pHexCert );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binKeyID );

    return ret;
}

int ACMEServer::procACME( const char *pPath, const BIN *pReq, QStringList& rspHeaders, BIN *pRsp )
{
    int ret = 0;
    QString strPath = pPath;
    QStringList listPath = strPath.split( "/" );
    int nSize = listPath.size();

    if( nSize < 1 ) return JSR_ERR;

    QString strCmd = listPath.at( nSize - 1 );
    QJsonDocument rspJDoc;
    QJsonObject rspJson;

    QJsonObject request;
    QByteArray rsp;
    ACMEObject acmeObj;
    QString strNonce;

    if( pReq && pReq->nLen > 0 )
    {
        QByteArray data;
        data.setRawData( (const char *)pReq->pVal, pReq->nLen );
        acmeObj.setObjectFromJson( data.data() );

        strNonce = acmeObj.getNonce();

        if( strNonce != nonce_ )
        {
            rspJson["type"] = "urn:ietf:params:acme:error:badNonce";
            rspJson["detail"] = "JWS has no anti-replay nonce";
            rspJson["status"] = 400;
            rspJDoc.setObject( rspJson );
            JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
            return JSR_ERR;
        }

        QString strKID = acmeObj.getKID();
        ACMEStat acme_stat;

        int count = acme_stats_.count( strKID );
        if( count > 0 )
        {
            acme_stat = acme_stats_[strKID];
        }
        else
        {
            acme_stats_.insert( strKID, acme_stat );
        }

        acme_stat.setNonce( strNonce );
    }

    if( strCmd.compare( kACME_Directory, Qt::CaseInsensitive ) == 0 )
    {
        ret = runACME_Directory( rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare( kACME_Location, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Location( rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare( kACME_Account, Qt::CaseInsensitive ) == 0 )
    {
        ret = runACME_Account( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_Order, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Order( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_Orders, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Orders( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_KeyChange, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_KeyChange( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_NewAccount, Qt::CaseInsensitive ) == 0 )
    {
        ret = runACME_NewAccount( acmeObj, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_NewNonce, Qt::CaseInsensitive ) == 0 )
    {
        BIN binRand = {0,0};
        ret = JS_PKI_genRandom( 8, &binRand );
        QString strNonce = QString( "Replay-Nonce: %1" ).arg( nonce_);
        rspHeaders.append( strNonce );
    }
    else if( strCmd.compare(kACME_NewOrder, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_NewOrder( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_RenewalInfo, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_RenewalInfo( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_RevokeCert, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_RevokeCert( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_NewAuthz, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_NewAuthz( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_Finalize, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Finalize( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_Certificate, Qt::CaseInsensitive ) == 0 )
    {
        BINList *pCertList = NULL;
        BINList *pCurList = NULL;

        ret = runACME_Certificate( &pCertList );

        pCurList = pCertList;

        while( pCurList )
        {
            pCurList = pCurList->pNext;
        }

        if( pCertList ) JS_BIN_resetList( &pCertList );
    }
    else if( strCmd.compare(kACME_Authorization, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Authorization( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_Challenge, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Challenge( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_Deactivate, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_Deactivate( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare(kACME_UpdateAccount, Qt::CaseInsensitive ) == 0 )
    {
        rsp.setRawData( (const char *)pReq->pVal, pReq->nLen );
        rspJDoc = QJsonDocument::fromJson( rsp );
        request = rspJDoc.object();

        ret = runACME_UpdateAccount( request, rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else
    {
        elog( QString( "Invalid ACME Path: %1" ).arg( strCmd ));
        return JSR_ERR2;
    }

    return ret;
}

int ACMEServer::procEST( const char *pPath, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    QString strPath;
    char *pPEM = NULL;
    BIN binCSR = {0,0};
    char *pCSR = NULL;
    int nType = -1;
    BIN binNewCert = {0,0};

    if( pPath == NULL ) return JSR_ERR;

    strPath = pPath;

    if( strPath.contains( kEST_CACerts ) == true )
    {
        JS_BIN_encodePEM( JS_PEM_TYPE_CERTIFICATE, &ca_cert_, &pPEM );
        JS_BIN_set( pRsp, (unsigned char *)pPEM, strlen( pPEM ));
    }
    else if( strPath.contains( kEST_SimpleEnroll ) == true  )
    {
        JS_BIN_string( pReq, &pCSR );
        JS_BIN_decodePEM( pCSR, &nType, &binCSR );

        ret = issueCert( &binCSR, &binNewCert );
        if( ret != 0 ) goto end;

        JS_BIN_encodePEM( JS_PEM_TYPE_CERTIFICATE, &binNewCert, &pPEM );
        JS_BIN_set( pRsp, (unsigned char *)pPEM, strlen( pPEM ));
    }
    else if( strPath.contains( kEST_SimpleReenroll ) == true )
    {
        JS_BIN_string( pReq, &pCSR );

        JS_BIN_decodePEM( pCSR, &nType, &binCSR );

        ret = issueCert( &binCSR, &binNewCert );
        if(ret != 0 ) goto end;

        JS_BIN_encodePEM( JS_PEM_TYPE_CERTIFICATE, &binNewCert, &pPEM );
        JS_BIN_set( pRsp, (unsigned char *)pPEM, strlen( pPEM ));
    }
    else
    {
        elog( QString( "Not supported path: %1").arg( pPath ));
    }


end :
    if( pPEM ) JS_free( pPEM );
    JS_BIN_reset( &binCSR );
    if( pCSR ) JS_free( pCSR );
    JS_BIN_reset( &binNewCert );

    return ret;
}

int ACMEServer::readReady()
{
    int ret = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    const char *pMethod = NULL;


    headers_.clear();
    content_len_ = 0;

    QByteArray Line;
    Line = client_->readLine();

    QList<QByteArray> first = Line.split( ' ' );
    if( first.size() >= 3 )
    {
        int nType = -1;
        char *pPath = NULL;

        method_ = first[0];
        path_ = first[1];
        version_ = first[2];

        JS_HTTP_getMethodPath( Line.data(), &nType, &pPath, &param_list_ );
        if( pPath ) JS_free( pPath );
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
        JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( path_.contains( "/EST" ) == true )
    {
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content_len_ ));
        JS_BIN_set( &binReq, (const unsigned char *)body_.data(), content_len_ );

        ret = procEST( path_.toStdString().c_str(), &binReq, &binRsp );
        if( ret != 0 )
        {
            elog( QString( "fail procCMP(%1)" ).arg( JERR(ret)) );
            goto end;
        }

        log( "ProcEST OK" );

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );

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

        if( binRsp.nLen > 0 )
        {
            rsp.setRawData( (const char *)binRsp.pVal, binRsp.nLen );
            client_->write( "\r\n" );
            client_->write( rsp );
        }

        client_->flush();
    }
    else if( path_.contains( "/ACME" ) == true )
    {
        QByteArray rsp;
        QStringList rspHeaders;

        log( QString( "Content Length: %1" ).arg( content_len_ ));
        JS_BIN_set( &binReq, (const unsigned char *)body_.data(), content_len_ );

        log( QString( "Body: %1" ).arg( body_.data() ));

        ret = procACME( path_.toStdString().c_str(), &binReq, rspHeaders, &binRsp );
        if( ret != 0 )
        {
            elog( QString( "fail procCMP(%1)" ).arg( JERR(ret)) );
            goto end;
        }

        log( "ProcACME OK" );

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );

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

        for( int i = 0; i < rspHeaders.size(); i++ )
        {
            QString strHeader = rspHeaders.at( i );
            rsp = strHeader.toUtf8();
            rsp += "r\n";
            client_->write( rsp );
        }

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
        log( QString( "Invalid URL: %1" ).arg(path_) );
        goto end;
    }


end :
    client_->disconnectFromHost();
    client_->deleteLater();
    client_ = nullptr;

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    resetState();

    return ret;
}

void ACMEServer::onEncrypted()
{
    QSslSocket *socket = qobject_cast<QSslSocket *>(sender());

    qDebug() << "TLS Connected";
}

void ACMEServer::onTLSReadyRead()
{
    buffer_ += tls_client_->readAll();

    processBuffer();
}

void ACMEServer::onTLSDisconnected()
{
    resetState();
}

void ACMEServer::incomingConnection( qintptr  socketDescriptor )
{
    log( "Connecting..." );

    if( nonce_.length() < 1 )
    {
        BIN binRand = {0,0};
        JS_PKI_genRandom( 8, &binRand );
        nonce_ = getHexString( &binRand );
        JS_BIN_reset( &binRand );
    }

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
        connect(tls_client_, &QSslSocket::readyRead, this, &ACMEServer::onTLSReadyRead);
        connect(tls_client_, &QSslSocket::disconnected, this, &ACMEServer::onTLSDisconnected);

        tls_client_->startServerEncryption();
    }
    else
    {
        client_ = new QTcpSocket;
        client_->setSocketDescriptor( socketDescriptor );

        connect( client_, &QTcpSocket::readyRead, this, &ACMEServer::readReady );
    }
}

void ACMEServer::processBuffer()
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
                processACME();
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
            processACME();
        }
    }
}

void ACMEServer::parseHeader(const QByteArray &header)
{
    headers_.clear();
    content_len_ = 0;

    QList<QByteArray> lines = header.split( '\n' );

    if( lines.isEmpty() ) return;

    QByteArray requestLine = lines.takeFirst().trimmed();
    QList<QByteArray> first = requestLine.split(' ');

    if( first.size() >= 3 )
    {
        char *pPath = NULL;
        int nType = -1;
        method_ = first[0];
        path_ = first[1];
        version_ = first[2];

        JS_HTTP_getMethodPath( requestLine.data(), &nType, &pPath, &param_list_ );
        if( pPath ) JS_free( pPath );
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

void ACMEServer::resetState()
{
    state_ = WaitingHeader;
    content_len_ = 0;
    headers_.clear();
    body_.clear();
    method_.clear();
    path_.clear();
    version_.clear();

    if( param_list_ ) JS_UTIL_resetNameValList( &param_list_ );
}

void ACMEServer::processACME()
{
    int ret = 0;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    int             nType = -1;
    const char      *pMethod = NULL;


    if( strcasecmp( path_.toStdString().c_str(), "/PING" ) == 0 )
    {
        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( path_.contains( "/EST" ) == true )
    {
        QByteArray rsp;

        log( QString( "Content Length: %1" ).arg( content_len_ ));
        JS_BIN_set( &binReq, (const unsigned char *)body_.data(), content_len_ );

        ret = procEST( path_.toStdString().c_str(), &binReq, &binRsp );
        if( ret != 0 )
        {
            elog( QString( "fail procCMP(%1)" ).arg( JERR(ret)) );
            goto end;
        }

        log( "ProcEST OK" );

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        //    log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "accept: application/cmp-response";
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "content-type: application/cmp-response";
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
    else if( strcasecmp( path_.toStdString().c_str(), "/ACME" ) == 0 )
    {
        QByteArray rsp;
        QStringList     rspHeaders;

        log( QString( "Content Length: %1" ).arg( content_len_ ));
        JS_BIN_set( &binReq, (const unsigned char *)body_.data(), content_len_ );

        ret = procACME( path_.toStdString().c_str(), &binReq, rspHeaders, &binRsp );
        if( ret != 0 )
        {
            elog( QString( "fail procCMP(%1)" ).arg( JERR(ret)) );
            goto end;
        }

        log( "ProcACME OK" );

        QString strLen = QString( "%1" ).arg( binRsp.nLen );

        pMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
        //    log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

        rsp = QByteArray( pMethod );
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "accept: application/cmp-response";
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "content-type: application/cmp-response";
        rsp += "\r\n";
        tls_client_->write( rsp );

        rsp = "Content-Length: ";
        rsp += strLen;
        rsp += "\r\n";
        tls_client_->write( rsp );

        for( int i = 0; i < rspHeaders.size(); i++ )
        {
            QString strHeader = rspHeaders.at( i );
            rsp = strHeader.toUtf8();
            rsp += "r\n";
            tls_client_->write( rsp );
        }

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
        log( QString( "Invalid URL: %1" ).arg( path_) );
        goto end;
    }


end :
    tls_client_->disconnectFromHost();
    tls_client_->deleteLater();
    tls_client_ = nullptr;

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

const QString ACMEServer::strACME_URL( const QString strCmd )
{
    QString strBase;

    if( tls_ == true )
        strBase = "https://localhost";
    else
        strBase = "http://localhost";

    strBase += QString( ":%1" ).arg( port_ );

    QString strURL = QString( "%1/ACME/%2" ).arg( strBase ).arg( strCmd );

    return strURL;
}

int ACMEServer::runACME_Directory( QJsonObject& rspJson )
{
    /*
    "keyChange": "https://localhost:14000/rollover-account-key",
    "meta": {
        "externalAccountRequired": false,
        "profiles": {
            "default": "The profile you know and love",
            "shortlived": "A short-lived cert profile, without actual enforcement"
        },
        "termsOfService": "data:text/plain,Do%20what%20thou%20wilt"
    },
    "newAccount": "https://localhost:14000/sign-me-up",
    "newNonce": "https://localhost:14000/nonce-plz",
    "newOrder": "https://localhost:14000/order-plz",
    "renewalInfo": "https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo",
    "revokeCert": "https://localhost:14000/revoke-cert"
    */

    rspJson[kACME_KeyChange] = strACME_URL(kACME_KeyChange);
    rspJson[kACME_NewAccount] = strACME_URL(kACME_NewAccount);
    rspJson[kACME_NewNonce] = strACME_URL(kACME_NewNonce);
    rspJson[kACME_NewOrder] = strACME_URL(kACME_NewOrder);
    rspJson[kACME_RenewalInfo] = strACME_URL(kACME_RenewalInfo);
    rspJson[kACME_RevokeCert] = strACME_URL(kACME_RevokeCert);

    return 0;
}

void ACMEServer::makeACMEFail( const QString strType, const QString strDetail, int nStatus, QJsonObject& rspJson )
{
    rspJson["type"] = strType;
    rspJson["detail"] = strDetail;
    rspJson["status"] = nStatus;
}

int ACMEServer::runACME_NewAccount( ACMEObject& acmeObj, QJsonObject& rspJson )
{
    int ret = 0;
    ACMEStat stat;
    BIN binPub = {0,0};
    QString strName;

    ret = acmeObj.getPubKey( &binPub );
    if( ret != JSR_OK )
    {
        elog( QString( "failed to get public key: %1" ).arg( ret ));
        goto end;
    }

    ret = acmeObj.verifySignature( &binPub );
    if( ret != JSR_VERIFY )
    {
        elog( QString( "failed to verify signature: %1" ).arg(ret ));
        goto end;
    }

    strName = acmeObj.getKID();
    acme_stats_.insert( strName, stat );

    rspJson["Status"] = "valid";
    rspJson["orders"] = strACME_URL( kACME_Orders );
    rspJson["contact"] = "";

    /* Key 는 Optional 값 */
    rspJson["pub_key"] = "";

/*
    {
        "status": "valid",
        "contact": [
            "mailto:aa@bb.com"
        ],
        "orders": "https://localhost:14000/list-orderz/745d0b2c3315699e",
        "key": {
            "kty": "RSA",
            "kid": "RSA2048",
            "alg": "RS256",
            "n": "uPfQkY4MJ-W_Sw6mRrzLtXWhnOGcyMU-6Y4pz8xBV1uICI3aBIxHWUulEUA6yeDyhFrs0Jp9u25InhKDIS0Va-n7LGhLscssDOyqluuvTrQeWFjtn9RIdbLitVF8Ij1jEHZX8ijE31vjJC06MaKbm_UP9sVAGLyIzgTJz6BXUz9sacOZ7MIwDlJO3v818ljOkTjxdFeZvl-cQ1vocW2LTP7RzifKJY7PumeaU0vQ9SVev2GXj9HoWpvEhr9M6aJ2Wt4wfJN247g-h_dcffqNBvh6An6uZiMKKkZZImu4c6rAUs8O2Ea_W2t93MbnsQgiLRQs1DtnUGxTUbE1lL2bgQ",
            "e": "AQAB"
        }
    }
*/

end :
    JS_BIN_reset( &binPub );

    return ret;
}

int ACMEServer::runACME_NewOrder( const QJsonObject request, QJsonObject& rspJson )
{
/*
    {
        "status": "pending",
        "expires": "2026-07-08T07:32:17Z",
        "identifiers": [
            {
                "type": "dns",
                "value": "example.com"
            }
        ],
        "profile": "shortlived",
        "finalize": "https://localhost:14000/finalize-order/b2Y8WKgmPGRk0DaEN8DToz9n97FTE-2eLZjcrT6CRD8",
        "authorizations": [
                "https://localhost:14000/authZ/-E9VbRbqYzKWSLIQugpJ9NKOGSQCbZXuOeiS2imC-WI"
        ]
    }
*/
    QJsonArray jArr;
    QJsonObject jObj;

    QJsonObject jReqObj;

    jArr.insert( 0, strACME_URL( kACME_Authorization ));

    rspJson["status"] = "valid";
    rspJson["expires"] = "2026-07-08T07:32:17Z";
    rspJson["identifiers"] = jArr;
    rspJson["profile"] = "shortlived";
    rspJson["finalize"] = strACME_URL( kACME_Finalize );

    return 0;
}

int ACMEServer::runACME_Authorization( const QJsonObject request, QJsonObject& rspJson )
{
    /*
    {
        "status": "pending",
        "identifier": {
            "type": "dns",
            "value": "example.com"
        },
        "challenges": [
            {
                "type": "tls-alpn-01",
                "url": "https://localhost:14000/chalZ/fyq7BVDYOE3t5oSRPAiED5zHT4FPuupmzdS_4B6nBMA",
                "token": "JxHyf4HLiNNFkZmluLVXh4ArUNqyGpv19R5rHHfH5-8",
                "status": "pending"
            },
            {
                "type": "http-01",
                "url": "https://localhost:14000/chalZ/d5Ot8SKEKfj9uMD_ffS3e2BepuF5uyzLxmx6WpTGCVk",
                "token": "oJwAsBqE6Hokcfl_nR2lWaNb0-TXq_XkCj9OdK6b_WY",
                "status": "pending"
            },
            {
                "type": "dns-01",
                "url": "https://localhost:14000/chalZ/T9LnChz4C5SVgVTQFhKaRkKO91RqKB_vGAKqDJ_7aw4",
                "token": "IHXyqVDbGFraOC2LdhgUhuV0O2wzoqgSBBllcjpFIXI",
                "status": "pending"
            },
            {
                "type": "dns-account-01",
                "url": "https://localhost:14000/chalZ/X6e1LF6HxvS_FFh0F1rqfyIn71at9YUjtDGV1Lu4InA",
                "token": "bEU5v9G6ratA3ZebG1-OPoB4PLf0qhODBhfnplyycQ0",
                "status": "pending"
            }
        ],
        "expires": "2026-07-07T14:50:40Z"
    }
    */

    QJsonArray jArr;
    QJsonObject jObj;
    QJsonObject jObj2;

    jObj["type"] = "http-01";
    jObj["url"] = "https://localhost:14000/chalZ/d5Ot8SKEKfj9uMD_ffS3e2BepuF5uyzLxmx6WpTGCVk";
    jObj["token"] = "oJwAsBqE6Hokcfl_nR2lWaNb0-TXq_XkCj9OdK6b_WY";
    jObj["status"] = "pending";

    jObj2["type"] = "dns-01";
    jObj2["url"] = "https://localhost:14000/chalZ/T9LnChz4C5SVgVTQFhKaRkKO91RqKB_vGAKqDJ_7aw4";
    jObj2["token"] = "IHXyqVDbGFraOC2LdhgUhuV0O2wzoqgSBBllcjpFIXI";
    jObj2["status"] = "pending";

    jArr.insert( 0, jObj );
    jArr.insert( 1, jObj2 );

    rspJson["status"] = "pending";
    rspJson["expires"] = "2026-07-07T14:50:40Z";
    rspJson["identifier"] = request["identifier"].toObject();

    return 0;
}

int ACMEServer::runACME_Finalize( const QJsonObject request, QJsonObject& rspJson )
{
    /*
    {
        "status": "processing",
        "expires": "2026-07-08T14:37:23Z",
        "identifiers": [
            {
                "type": "dns",
                "value": "example.com"
            }
        ],
        "profile": "default",
        "finalize": "https://localhost:14000/finalize-order/NpfXMVaLW8-UZBIkOQHLeiVaAGts39QSVtTSEDu42-w",
        "authorizations": [
            "https://localhost:14000/authZ/7v5ap9bhdtX61MFBqHUXTpMd62DFi1H90EHbW-rOxBo"
        ]
    }
    */
    QJsonArray jArr;
    jArr.insert( 0, strACME_URL( kACME_Authorization ));

    QJsonArray jIDArr;
    QJsonObject jIDObj;
    jIDObj["type"] = "dns";
    jIDObj["value"] = "example.com";

    jIDArr.insert( 0, jIDObj );

    rspJson["status"] = "processing";
    rspJson["expires"] = "2026-07-08T14:37:23Z";
    rspJson["identifiers"] = jIDArr;
    rspJson["finalize"] = strACME_URL( kACME_Finalize );
    rspJson["autorizaions"] = jArr;

    return 0;
}

int ACMEServer::runACME_Challenge( const QJsonObject request, QJsonObject& rspJson )
{
    /*
    {
        "type": "dns-01",
        "url": "https://localhost:14000/chalZ/sW0wRYjRAe7twtBn5OE56BEpaJNqJKcfyk2DarOPGJU",
        "token": "slUfb4u4H-Dw64Fq9wWF6BvqmbCDUlVj5tNRJBOXtLU",
        "status": "processing"
    }
    */

    return 0;
}

int ACMEServer::runACME_Account( const QJsonObject request, QJsonObject& rspJson )
{
    /*
    {
        "contact": [
            "mailto:jykim74@gmail.com"
        ],
        "key": {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "RSA2048",
            "kty": "RSA",
            "n": "o-uSO8dWrkNNANT0IGzSh6mTHZRlUMuPvgiTtHU0361K81FuNNtRKm3kf91SoGFoFZvp4zUKulZE5KkSeXHpGW7NZjwrjXZM-pXY_sn2DJO_ACnDZSc3Tkfkc-Ye2rqwPbSvmH7SVe4915t_V4M1-vzQXQwEMP1BAD03-sxr_gnq5x-3VKYgXvtaQiUIh0OvdaQA44RRnFyxXv-hhN3p-4sPhN2tzlrlVQNVse1JAzhwUOZ4_VF5Lq6DE9c0F3r_os_42HebKLNP5l-OyvFgPfCi-DlAJ0n_S0q34OGBCyz4KKlKXODDhtzlVmLyl-lvO1ho05V2PqvQ7bt8K1B3Sw"
        },
        "orders": "https://localhost:14000/list-orderz/50bf9ebf4776792b",
        "status": "valid"
    }
    */

    return 0;
}

int ACMEServer::runACME_Location( QJsonObject& rspJson )
{
    /*
    {
        "status": "valid",
        "expires": "2026-07-14T06:53:16Z",
        "identifiers": [
            {
                "type": "dns",
                "value": "example.com"
            }
        ],
        "profile": "shortlived",
        "finalize": "https://localhost:14000/finalize-order/x6OPEYHH0Nj5AYXhREWBlf78d250j5jRzEOd0SKIIy8",
        "authorizations": [
            "https://localhost:14000/authZ/C5uDmRFsgcRtprXWjc6MozzaTfb6NXl-DvfNuW7jNLI"
        ],
        "certificate": "https://localhost:14000/certZ/119eadf8f6d15ef2"
    }
    */

    return 0;
}

int ACMEServer::runACME_Certificate( BINList **ppCertList )
{
    /*
    -----BEGIN CERTIFICATE-----
    MIICWjCCAgCgAwIBAgIIEZ6t+PbRXvIwCgYIKoZIzj0EAwIwKDEmMCQGA1UEAxMd
    UGViYmxlIEludGVybWVkaWF0ZSBDQSA0NTNjYzAwHhcNMjYwNzEzMDY1NDA5WhcN
    MjYwNzE5MDY1NDA4WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
    lMVYefPBEl6H6tzUWLdBpcOWorHuvk/cCVyhVKg64g5Iq00ll0yrGJyVNdFlYbJG
    87qcKw8jCujbG3cxo9JvoDUi8fSZue+UQXGKYc/QjFvUZXKpfz+LiKCJOYjLRwlG
    AWw+ZycuEsdj1ZMfaTdbLJ1As+K/KscMUtwukrBu1eCa77AB+1UfRZni5/1aLiDL
    6u1YeyQwwyMif5oMg+O3xSf+TWNHeVtodq9FvB6CptBtfwHLZtIS0aDeqtSs36yC
    xhYSaiJAktC+N5BvNVYNYa1oWpD5pl0v4wJsO7Aj6uhhcEy2wowie6UJ9xkvKd9G
    BTu9bWykvyLa+cyhCCO8lwIDAQABo3EwbzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
    BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSqjj2QiPkn
    PE7Yy+/9zjUCsfUxvjAZBgNVHREBAf8EDzANggtleGFtcGxlLmNvbTAKBggqhkjO
    PQQDAgNIADBFAiEAv/3ypSJkz4fUix5j6oaov55w4s4IONP8dOyxx3lN0VUCIHZb
    NayY7oMLa/IZque8J+twmQ9r9rwDqIacG1c2LWKH
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIBuTCCAV6gAwIBAgIIHQpShl3bTQcwCgYIKoZIzj0EAwIwIDEeMBwGA1UEAxMV
    UGViYmxlIFJvb3QgQ0EgMzUzMTA2MCAXDTI2MDcxMzAxMjIxNloYDzIwNTYwNzEz
    MDEyMjE2WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDQ1M2Nj
    MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGhG7Vuv0uGddOhJIuHz9ZNe8S+1
    ztJj+9dlvic/lbtcsaRNH4L199xShV89obxrp5hNrzvPiyBL6r6VVBovzZ6jeDB2
    MA4GA1UdDwEB/wQEAwIChDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8E
    BTADAQH/MB0GA1UdDgQWBBSqjj2QiPknPE7Yy+/9zjUCsfUxvjAfBgNVHSMEGDAW
    gBTU2o3RyS23b5iuxsmZNG6ByC6bVDAKBggqhkjOPQQDAgNJADBGAiEAmZlp+lel
    6GeBtEs5Tq/WbCqxwfzuebv3VlkoqQ9Rw9gCIQCC2qc+cuQSXrUZvWbtLI3Oyn5C
    T3QXc3+LeljOLrqBTA==
    -----END CERTIFICATE-----
    */

    return 0;
}

int ACMEServer::runACME_Order( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_Orders( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_KeyChange( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_RenewalInfo( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_RevokeCert( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_NewAuthz( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_Deactivate( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}

int ACMEServer::runACME_UpdateAccount( const QJsonObject request, QJsonObject& rspJson )
{
    return 0;
}
