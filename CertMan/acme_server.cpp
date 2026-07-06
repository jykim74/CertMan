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

#include "acme_server.h"

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

    if( strCmd.compare( kACME_Directory, Qt::CaseInsensitive ) == 0 )
    {
        ret = runACME_Directory( rspJson );

        rspJDoc.setObject( rspJson );
        JS_BIN_set( pRsp, (unsigned char *)rspJDoc.toJson().data(), rspJDoc.toJson().length() );
    }
    else if( strCmd.compare( kACME_Location, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare( kACME_Account, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Order, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Orders, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_KeyChange, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_NewAccount, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_NewNonce, Qt::CaseInsensitive ) == 0 )
    {
        BIN binRand = {0,0};
        ret = JS_PKI_genRandom( 8, &binRand );
        QString strNonce = QString( "Replay-Nonce: %1" ).arg( getHexString( &binRand ));
        rspHeaders.append( strNonce );
        JS_BIN_reset( &binRand );
    }
    else if( strCmd.compare(kACME_NewOrder, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_RenewalInfo, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_RevokeCert, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_NewAuthz, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Finalize, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Certificate, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Authorization, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Challenge, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_Deactivate, Qt::CaseInsensitive ) == 0 )
    {

    }
    else if( strCmd.compare(kACME_UpdateAccount, Qt::CaseInsensitive ) == 0 )
    {

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
        //    log( QString( "Response: %1" ).arg( getHexString( &binRsp )));

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

int ACMEServer::runACME_NewAcount( const QJsonObject request, QJsonObject& rspJon )
{
    return 0;
}
