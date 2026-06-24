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

#include "ca_server.h"

CAServer::CAServer( QObject *parent ) :
    QTcpServer(parent)
{
    log_edit_ = nullptr;
    ca_num_ = -1;

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

void CAServer::setCANum( int nNum )
{
    ca_num_ = nNum;
}

void CAServer::setProfileNum( int nNum )
{
    profile_num_ = nNum;
}

void CAServer::setCAPriKey( const BIN *pPriKey, bool bP11 )
{
    JS_BIN_reset( &ca_pri_key_ );
    JS_BIN_copy( &ca_pri_key_, pPriKey );
    p11_ = bP11;
}

void CAServer::startServer( int nPort )
{
    if( !this->listen( QHostAddress::Any, nPort) )
    {
        log( "Could not start server" );
    }
    else
    {
        log( QString( "Listening to port: %1" ).arg( nPort ));
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

int CAServer::makeCert( const JIssueCertInfo *pIssueCertInfo, BIN *pCert )
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

int CAServer::procCMP( const BIN *pReq, BIN *pRsp )
{
    int ret = 0;

    JCMPReqInfo sReqInfo;
    int nReqType = -1;
    void *pSrvCTX = NULL;
    DBMgr* dbMgr = manApplet->dbMgr();
    UserRec userRec;
    CertRec certRec;
    char sKID[1024];
    BIN binSignCert = {0,0};
    QString strAuthCode;
    QString strDN;
    JStrList *pITAVList = NULL;

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));
    memset( sKID, 0x00, sizeof(sKID));

    pSrvCTX = JS_CMP_getSrvCTX( NULL, &ca_cert_, &ca_pri_key_ );
    if( pSrvCTX == NULL )
    {
        log( QString( "failed to get server ctx" ) );
        goto end;
    }

    ret = JS_CMP_decodeReq( pReq, &sReqInfo, &pITAVList );
    if( ret != JSR_OK )
    {
        goto end;
    }

    memcpy( sKID, sReqInfo.binSendKID.pVal, sReqInfo.binSendKID.nLen );
    nReqType = sReqInfo.nType;
    strDN = sReqInfo.pSubjectDN;

    log( QString( "KID: %1" ).arg( sKID ));

    ret = dbMgr->getUserRecByRefNum( sKID, userRec );
    if( ret == JSR_OK )
    {
        strAuthCode = userRec.getAuthCode();
        if( strDN.length() < 1 ) strDN = QString( "CN=%1" ).arg( userRec.getName() );
        log( QString( "AuthCode: %1" ).arg( strAuthCode ));
    }
    else
    {
        ret = dbMgr->getCertRecByKeyHash( sKID, certRec );
        if( ret != JSR_OK )
        {
            log( "There is no certificate" );
            goto end;
        }

        if( strDN.length() < 1 ) strDN = certRec.getSubjectDN();
        JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binSignCert );
    }


    switch (nReqType) {
    case JS_CMP_PKIBODY_GENM:
        ret = runCMP_GENM( pSrvCTX, pReq, strAuthCode, &binSignCert, pRsp );
        break;
    case JS_CMP_PKIBODY_IR:
    case JS_CMP_PKIBODY_CR:
        ret = runCMP_IR( pSrvCTX, pReq, strAuthCode, &sReqInfo.binPubKey, strDN, pRsp );
        break;

    case JS_CMP_PKIBODY_P10CR:
        ret = runCMP_P10CR( pSrvCTX, pReq, strAuthCode, &sReqInfo.binPubKey, strDN, pRsp );
        break;

    case JS_CMP_PKIBODY_KUR:
        ret = runCMP_KUR( pSrvCTX, pReq, certRec, &sReqInfo.binPubKey, pRsp );
        break;

    case JS_CMP_PKIBODY_RR:
        ret = runCMP_RR( pSrvCTX, pReq, certRec, sReqInfo.nNum, pRsp );
        break;

    case JS_CMP_PKIBODY_CERTCONF:
        ret = runCMP_CertConf( pSrvCTX, pReq, pRsp );
        break;
    default:
        ret = JSR_INVALID_ALG;
        break;
    }

end :
    if( ret != JSR_OK )
    {
        log( QString( "CMP Error Status: %1").arg( JERR(ret)) );
        ret = JS_CMP_encodeRspError( pSrvCTX, pReq, strAuthCode.length() > 1 ? strAuthCode.toStdString().c_str() : NULL, &binSignCert, ret, pRsp );
    }
    else
    {
        log( QString( "CMP Run OK [Type: %1]" ).arg( nReqType ));
    }

    JS_CMP_resetReqInfo( &sReqInfo );
    JS_BIN_reset( &binSignCert );
    if( pSrvCTX ) JS_CMP_release( &pSrvCTX );
    if( pITAVList ) JS_UTIL_resetStrList( &pITAVList );

    return ret;
}

int CAServer::runSCEP_PKIReq( const BIN *pSignCert, const BIN *pData, BIN *pSignedData )
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

    ret = JS_PKI_getReqInfo( pData, &sReqInfo, 1, NULL );
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

    ret = JS_SCEP_genSignedDataWithoutSign( &binNewCert, NULL, pSignedData );
    if( ret != 0 )
    {
        log( QString( "fail to make response signeddata : %1" ).arg( ret ));
        goto end;
    }

    log( QString( "SignedData Length : %1" ).arg( pSignedData->nLen ));

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

int CAServer::runSCEP_GetCRL( const BIN *pSignCert, const BIN *pData, BIN *pSignedData )
{
    int ret = 0;
    PKCS7_ISSUER_AND_SERIAL *pXIAS = NULL;
    const unsigned char *pPos = pData->pVal;
    BIN binCRL = {0,0};
    CRLRec crlRec;

    DBMgr* dbMgr = manApplet->dbMgr();

    pXIAS = d2i_PKCS7_ISSUER_AND_SERIAL( NULL, &pPos, pData->nLen );
    ret = dbMgr->getLatestCRLRec( ca_num_, crlRec );

    if( ret != JSR_OK )
    {
        log( QString( "fail to get latest CRL [IssuerNum: %1]" ).arg( ret) );
        goto end;
    }

    JS_BIN_decodeHex( crlRec.getCRL().toStdString().c_str(), &binCRL );

    ret = JS_SCEP_genSignedDataWithoutSign( NULL, &binCRL, pSignedData );

end :
    if( pXIAS ) PKCS7_ISSUER_AND_SERIAL_free( pXIAS );
    JS_BIN_reset( &binCRL );

    return ret;
}

int CAServer::workSCEPOperation( const BIN *pPKIReq, BIN *pCertRsp )
{
    int ret = 0;
    int nType = 0;
    int nFlag = 0;

    BIN binSignCert = {0,0};
    BIN binSenderNonce = {0,0};
    char *pTransID = NULL;
    BIN binData = {0,0};
    BIN binDevData = {0,0};
    BIN binResData = {0,0};
    BIN binEnvData = {0,0};

    BIN binSrvSenderNonce = {0,0};
    char sResMsg[1024];

    bool bP11 = true;

    memset( sResMsg, 0x00, sizeof(sResMsg));

    ret = JS_SCEP_verifyParseSignedData( pPKIReq, &nType, &binSignCert, &binSenderNonce, &pTransID, &binData );
    if( ret != 0 )
    {
        log( QString( "fail to veriyf signeddata : %1" ).arg( ret ));
        goto end;
    }

    if( bP11 )
    {
        ret = JS_PKCS7_makeDevelopedDataByP11( &binData, &ca_pri_key_, NULL, &ca_cert_, nFlag, &binDevData, sResMsg );
    }
    else
    {
        ret = JS_PKCS7_makeDevelopedData( &binData, &ca_pri_key_, &ca_cert_, nFlag, &binDevData, sResMsg );
    }

    if( ret != 0 )
    {
        log( QString( "fail to develop data : %1" ).arg( ret ));
        goto end;
    }

    if( nType == JS_SCEP_REQUEST_PKCSREQ )
    {
        log( QString( "REQUEST_PKCSREQ" ) );
        ret = runSCEP_PKIReq( &binSignCert, &binDevData, &binResData );
//        if( ret == 0 ) JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_SCEP_PKCS_REQ, "Admin", NULL );
    }
    else if( nType == JS_SCEP_REQUEST_GETCRL )
    {
        log( "REQUEST_GETCRL" );
        ret = runSCEP_GetCRL( &binSignCert, &binDevData, &binResData );
//        if( ret == 0 ) JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_SCEP_GET_CRL, "Admin", NULL );
    }
    else if( nType == JS_SCEP_REQUEST_GETCERT )
    {
        log( "REQUEST_GETCERT" );
        elog( "Not implemented" );
    }
    else if( nType == JS_SCEP_REQUEST_GETCERTINIT )
    {
        log( "REQUEST_GETCERTINIT" );
        elog( "Not implemented" );
    }
    else
    {
        log( "Invalid request type : %d", nType );
        ret = -1;
        goto end;
    }

    ret = JS_PKCS7_makeEnvelopedData( "aes-256-cbc", &binResData, &binSignCert, nFlag, &binEnvData );

    JS_PKI_genRandom( 16, &binSrvSenderNonce );

    if( bP11 )
    {
        ret = JS_SCEP_makeSignedDataByP11( JS_SCEP_REPLY_CERTREP,
                                          "SHA256",
                                          &binEnvData,
                                          &ca_pri_key_,
                                          NULL,
                                          &ca_cert_,
                                          &binSrvSenderNonce,
                                          &binSenderNonce,
                                          pTransID,
                                          "0",
                                          pCertRsp );
    }
    else
    {
        ret = JS_SCEP_makeSignedData( JS_SCEP_REPLY_CERTREP,
                                     "SHA256",
                                     &binEnvData,
                                     &ca_pri_key_,
                                     &ca_cert_,
                                     &binSrvSenderNonce,
                                     &binSenderNonce,
                                     pTransID,
                                     "0",
                                     pCertRsp );
    }

end :
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binSenderNonce );
    JS_BIN_reset( &binSrvSenderNonce );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDevData );
    if( pTransID ) JS_free( pTransID );
    JS_BIN_reset( &binResData );
    JS_BIN_reset( &binEnvData );

    return ret;
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
        ret = workSCEPOperation( pReq, pRsp );
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
            elog( QString( "fail procCMP(%1)" ).arg( JERR(ret)) );
            goto end;
        }

        log( "ProcCMP OK" );

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
//    client_->waitForDisconnected();
    client_->deleteLater();

    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );
    if( pPath ) JS_free( pPath );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    return ret;
}

void CAServer::incomingConnection( qintptr  socketDescriptor )
{
    log( "Connecting..." );

    client_ = new QTcpSocket;
    client_->setSocketDescriptor( socketDescriptor );

    connect( client_, &QTcpSocket::readyRead, this, &CAServer::readReady );
}

int CAServer::runCMP_GENM( void *pSrvCTX, const BIN *pReq, const QString strAuthCode, const BIN *pSignCert, BIN *pRsp )
{
    int ret = 0;

    if( strAuthCode.length() > 1 )
    {
        ret = JS_CMP_encodeRspGENM( pSrvCTX, pReq, &ca_cert_, strAuthCode.toStdString().c_str(), pRsp );
    }
    else
    {
        ret = JS_CMP_encodeRspGENM_Cert( pSrvCTX, pReq, &ca_cert_, pSignCert, pRsp );
    }

    return ret;
}

int CAServer::runCMP_IR( void *pSrvCTX, const BIN *pReq, const QString strAuthCode, const BIN *pPubKey,const QString strDN,BIN *pRsp )
{
    int ret = 0;
    BIN binNewCert = {0,0};
    DBMgr* dbMgr = manApplet->dbMgr();
    CertProfileRec profileRec;
    QList<ProfileExtRec> profileExtList;
    CertRec certRec;

    time_t now_t = time(NULL);
    time_t notBefore = 0;
    time_t notAfter = 0;

    JIssueCertInfo sIssueCertInfo;
    JCertInfo   sCertInfo;

    int nKeyType = -1;
    QString strSerial;
    BIN binKeyID = {0,0};

    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    dbMgr->getCertProfileRec( profile_num_, profileRec );

    JS_PKI_getPeriod( profileRec.getNotBefore(),
                     profileRec.getNotAfter(),
                     now_t,
                     &notBefore,
                     &notAfter );

    nKeyType = JS_PKI_getPubKeyType( pPubKey );
    JS_PKI_getKeyIdentifier( pPubKey, &binKeyID );

    strSerial = QString("%1").arg( dbMgr->getNextVal( "TB_CERT" ) );

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                            profileRec.getVersion(),
                            strSerial.toStdString().c_str(),
                            profileRec.getHash().toStdString().c_str(),
                            strDN.toStdString().c_str(),
                            notBefore,
                            notAfter,
                            nKeyType,
                            getHexString( pPubKey).toStdString().c_str() );

    ret = makeCert( &sIssueCertInfo, &binNewCert );
    if( ret != 0 )
    {
        log( QString( "fail to make certificate : %1").arg( JERR(ret) ) );
        goto end;
    }

    ret = JS_CMP_encodeRspIR( pSrvCTX, pReq, strAuthCode.toStdString().c_str(), &binNewCert, pRsp );
    if( ret != 0 )
    {
        log( QString( "fail to encodeRspIR : %1").arg( JERR(ret) ) );
        goto end;
    }

    ret = JS_PKI_getCertInfo( &binNewCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        log( QString( "fail to get certificate information: %1" ).arg( JERR(ret) ));
        goto end;
    }

    certRec.setRegTime( now_t );
    certRec.setNotBefore( notBefore );
    certRec.setNotAfter( notAfter );
    certRec.setSignAlg( sCertInfo.pSignAlgorithm );
    certRec.setCert( getHexString( &binNewCert ));
    certRec.setIssuerNum( ca_num_ );
    certRec.setSubjectDN( sCertInfo.pSubjectName );
    certRec.setSerial( sCertInfo.pSerial );
    certRec.setDNHash( sCertInfo.pDNHash );
    certRec.setKeyHash( getHexString( &binKeyID) );

    dbMgr->addCertRec( certRec );

end :
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binKeyID );
    JS_BIN_reset( &binNewCert );

    return ret;
}

int CAServer::runCMP_P10CR( void *pSrvCTX, const BIN *pReq, const QString strAuthCode, const BIN *pPubKey,const QString strDN,BIN *pRsp  )
{
    return runCMP_IR( pSrvCTX, pReq, strAuthCode, pPubKey, strDN, pRsp );
}

int CAServer::runCMP_RR( void *pSrvCTX, const BIN *pReq, CertRec certRec, int nReason, BIN *pRsp )
{
    int ret = 0;
    RevokeRec revoke;

    DBMgr* dbMgr = manApplet->dbMgr();
    time_t now_t = time(NULL);
    BIN binCert = {0,0};

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );

    revoke.setCertNum( certRec.getNum() );
    revoke.setIssuerNum( certRec.getIssuerNum() );
    revoke.setSerial( certRec.getSerial() );
    revoke.setReason( nReason );
    revoke.setRevokeDate( now_t );
    revoke.setCRLDP( certRec.getCRLDP() );

    dbMgr->addRevokeRec( revoke );
    dbMgr->modCertStatus( certRec.getNum(), JS_CERT_STATUS_REVOKE );

    ret = JS_CMP_encodeRspRR( pSrvCTX, pReq, &binCert, pRsp );
    if( ret != 0 )
    {
        log( QString( "fail to encode RSP : %1").arg( JERR(ret) ) );
        goto end;
    }

end :
    JS_BIN_reset( &binCert );
    return ret;
}

int CAServer::runCMP_KUR( void *pSrvCTX, const BIN *pReq, CertRec certRec, const BIN *pPubKey, BIN *pRsp )
{
    return 0;    int ret = 0;
    BIN binNewCert = {0,0};
    DBMgr* dbMgr = manApplet->dbMgr();
    CertProfileRec profileRec;
    QList<ProfileExtRec> profileExtList;
    CertRec certNewRec;

    time_t now_t = time(NULL);
    time_t notBefore = 0;
    time_t notAfter = 0;

    JIssueCertInfo sIssueCertInfo;
    JCertInfo   sCertInfo;

    int nKeyType = -1;
    QString strSerial;
    BIN binKeyID = {0,0};
    QString strDN = certRec.getSubjectDN();

    BIN binCert = {0,0};
    RevokeRec revoke;

    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    dbMgr->getCertProfileRec( profile_num_, profileRec );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );

    JS_PKI_getPeriod( profileRec.getNotBefore(),
                     profileRec.getNotAfter(),
                     now_t,
                     &notBefore,
                     &notAfter );

    nKeyType = JS_PKI_getPubKeyType( pPubKey );
    JS_PKI_getKeyIdentifier( pPubKey, &binKeyID );

    strSerial = QString("%1").arg( dbMgr->getNextVal( "TB_CERT" ) );

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                            profileRec.getVersion(),
                            strSerial.toStdString().c_str(),
                            profileRec.getHash().toStdString().c_str(),
                            strDN.toStdString().c_str(),
                            notBefore,
                            notAfter,
                            nKeyType,
                            getHexString( pPubKey).toStdString().c_str() );

    ret = makeCert( &sIssueCertInfo, &binNewCert );
    if( ret != 0 )
    {
        log( QString( "fail to make certificate : %1").arg( JERR(ret) ) );
        goto end;
    }

    ret = JS_CMP_encodeRspKUR( pSrvCTX, pReq, &binCert, &binNewCert, pRsp );
    if( ret != 0 )
    {
        log( QString( "fail to encode RSP : %1").arg( JERR(ret) ) );
        goto end;
    }

    ret = JS_PKI_getCertInfo( &binNewCert, &sCertInfo, NULL );
    if( ret != 0 )
    {
        log( QString( "fail to get certificate information: %1" ).arg( JERR(ret) ));
        goto end;
    }


    revoke.setCertNum( certRec.getNum() );
    revoke.setIssuerNum( certRec.getIssuerNum() );
    revoke.setSerial( certRec.getSerial() );
    revoke.setReason( JS_PKI_REVOKE_REASON_KEY_COMPROMISE );
    revoke.setRevokeDate( now_t );
    revoke.setCRLDP( certRec.getCRLDP() );

    dbMgr->addRevokeRec( revoke );
    dbMgr->modCertStatus( certRec.getNum(), JS_CERT_STATUS_REVOKE );

    certNewRec.setRegTime( now_t );
    certNewRec.setNotBefore( notBefore );
    certNewRec.setNotAfter( notAfter );
    certNewRec.setSignAlg( sCertInfo.pSignAlgorithm );
    certNewRec.setCert( getHexString( &binNewCert ));
    certNewRec.setIssuerNum( ca_num_ );
    certNewRec.setSubjectDN( sCertInfo.pSubjectName );
    certNewRec.setSerial( sCertInfo.pSerial );
    certNewRec.setDNHash( sCertInfo.pDNHash );
    certNewRec.setKeyHash( getHexString( &binKeyID) );

    dbMgr->addCertRec( certNewRec );

end :
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binKeyID );
    JS_BIN_reset( &binNewCert );
    JS_BIN_reset( &binCert );

    return ret;}

int CAServer::runCMP_CertConf( void *pSrvCTX, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;

    ret = JS_CMP_encodeRspCertConf( pSrvCTX, pReq, pRsp );
    if( ret != 0 )
    {
        log( QString( "fail to encode RSP : %1").arg( JERR(ret) ) );
        goto end;
    }

end :

    return ret;
}
