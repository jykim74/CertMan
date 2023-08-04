#include "make_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "req_rec.h"
#include "cert_rec.h"
#include "user_rec.h"
#include "cert_profile_rec.h"
#include "key_pair_rec.h"
#include "db_mgr.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "commons.h"
#include "settings_mgr.h"

#include "js_gen.h"
#include "js_kms.h"



QString getSignAlg( const QString strAlg, const QString strHash )
{
    QString strSignAlgorithm;

    strSignAlgorithm = strHash.toUpper();
    strSignAlgorithm += "WITH";

    if( strAlg == "EC" || strAlg == "ECC" )
        strSignAlgorithm += "ECDSA";
    else
        strSignAlgorithm += strAlg.toUpper();

    return strSignAlgorithm;
}

MakeCertDlg::MakeCertDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mReqNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(reqChanged(int)));
    connect( mIssuerNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(issuerChanged(int)));
    connect( mProfileNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(profileChanged(int)));
    connect( mSelfSignCheck, SIGNAL(clicked()), this, SLOT(clickSelfSign()));
    connect( mUseCSRFileCheck, SIGNAL(clicked()), this, SLOT(clickUseCSRFile()));
    connect( mCSRFileFindBtn, SIGNAL(clicked()), this, SLOT(findCSRFile()));
}

MakeCertDlg::~MakeCertDlg()
{
    req_list_.clear();
    ca_cert_list_.clear();
    cert_profile_list_.clear();
}

void MakeCertDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void MakeCertDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    req_list_.clear();

    dbMgr->getReqList( 0, req_list_ );
    if( req_list_.size() <= 0 )
    {
        manApplet->warningBox( tr( "There is no request"), this );
        return;
    }

    for( int i = 0; i < req_list_.size(); i++ )
    {
        ReqRec reqRec = req_list_.at(i);
        mReqNameCombo->addItem( reqRec.getName() );
    }

    ca_cert_list_.clear();

    dbMgr->getCACertList( ca_cert_list_ );
    for( int i=0; i < ca_cert_list_.size(); i++ )
    {
        CertRec certRec = ca_cert_list_.at(i);
        mIssuerNameCombo->addItem( certRec.getSubjectDN() );
    }

    cert_profile_list_.clear();

    dbMgr->getCertProfileListByType( JS_PKI_PROFILE_TYPE_CERT, cert_profile_list_ );

    if( cert_profile_list_.size() <= 0 )
    {
        manApplet->warningBox( tr( "There is no certificate profile"), this );
        return;
    }

    for( int i=0; i < cert_profile_list_.size(); i++ )
    {
        CertProfileRec certProfileRec = cert_profile_list_.at(i);
        mProfileNameCombo->addItem( certProfileRec.getName() );
    }

    setSubjectDN();

    if( req_list_.size() <= 0 ) mUseCSRFileCheck->setChecked(true);
    clickUseCSRFile();

    if( manApplet->isPRO() == false )
    {
        mUserGroup->hide();
        resize( width(), height() - 120 );
    }
}

void MakeCertDlg::setSubjectDN()
{
    CertProfileRec   profile = cert_profile_list_.at(mProfileNameCombo->currentIndex());

    if( profile.getDNTemplate() == "#CSR" )
    {
        if( req_list_.size() > 0 )
        {
            ReqRec req = req_list_.at( mReqNameCombo->currentIndex() );

            mSubjectDNText->setText( req.getDN() );
        }
    }
    else
    {
        mSubjectDNText->setText( profile.getDNTemplate() );
    }
}

QString MakeCertDlg::getRealSubjectDN()
{
    QString strDN = mSubjectDNText->text();

    return getReplacedValue( strDN );
}

QString MakeCertDlg::getReplacedValue( QString &strVal )
{
    char        *pReplace = NULL;
    QString     strReplace;

    QString strUserName = mUserNameText->text();
    QString strSSN = mSSNText->text();
    QString strEmail = mEmailText->text();

    JNameValList    *pNameValList = NULL;

    JS_UTIL_createNameValList2( JS_PKI_TEMPLATE_NAME, strUserName.toStdString().c_str(), &pNameValList );
    JS_UTIL_appendNameValList2( pNameValList, JS_PKI_TEMPLATE_SSN, strSSN.toStdString().c_str() );
    JS_UTIL_appendNameValList2( pNameValList, JS_PKI_TEMPLATE_EMAIL, strEmail.toStdString().c_str() );

    JS_PKI_getReplacedDN( strVal.toStdString().c_str(), pNameValList, &pReplace );

    if( pReplace )
    {
        strReplace = pReplace;
        JS_free( pReplace );
    }
    else
    {
        strReplace = strVal;
    }

    if( pNameValList ) JS_UTIL_resetNameValList( &pNameValList );

    return strReplace;
}

void MakeCertDlg::setFixIssuer(QString strIssuerName)
{
    mIssuerNameCombo->setCurrentText( strIssuerName );
//    mIssuerNameCombo->setDisabled(true);
//    mIssuerAlgorithmText->setDisabled(true);
//    mIssuerOptionText->setDisabled(true);
//    mSelfSignCheck->setDisabled(true);
}

void MakeCertDlg::setReqNum( int nReqNum )
{
    if( nReqNum < 0 ) return;

    ReqRec reqRec;
    DBMgr* dbMgr = manApplet->dbMgr();
    dbMgr->getReqRec( nReqNum, reqRec );

    if( reqRec.getName().length() > 0 )
        mReqNameCombo->setCurrentText( reqRec.getName() );
}

void MakeCertDlg::accept()
{
    int ret = 0;
    JIssueCertInfo sIssueCertInfo;
    JCertInfo sMadeCertInfo;
    JReqInfo    sReqInfo;

    BIN binCSR = {0,0};
    BIN binSignPri = {0,0};
    BIN binSignCert = {0,0};
    BIN binCert = {0,0};
    char *pHexCert = NULL;
    bool bCA = false;
    BIN binPub = {0,0};
    BIN binKeyID = {0,0};

    char *pHexCRLDP = NULL;
    char *pCRLDP = NULL;

    CertRec madeCertRec;
    JExtensionInfoList *pCertExtInfoList = NULL;
    JExtensionInfoList *pCSRExtInfoList = NULL;
    JExtensionInfoList *pExtInfoList = NULL;
    JExtensionInfoList *pMadeExtInfoList = NULL;

    QTextCodec *codec = QTextCodec::codecForName("UTF-16");
    QByteArray ba;

    UserRec userRec;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    bool bSelf = mSelfSignCheck->isChecked();

    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sMadeCertInfo, 0x00, sizeof(sMadeCertInfo));
    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    if( manApplet->isLicense() == false )
    {
        int nTotalCnt = dbMgr->getCertCountAll();

        if( nTotalCnt >= JS_NO_LICENSE_CERT_LIMIT_COUNT )
        {
            manApplet->warningBox( tr( "You can not make certificate more than %1 certificates in no license")
                                   .arg( JS_NO_LICENSE_CERT_LIMIT_COUNT ), this );
            return;
        }
    }

    if( mUseCSRFileCheck->isChecked() )
    {
        if( mCSRFilePathText->text().length() <= 0 )
        {
            manApplet->warningBox( tr( "You have to find CSR file"), this );
            return;
        }
    }
    else
    {
        if( req_list_.size() <= 0 )
        {
            manApplet->warningBox( tr("There is no request"), this );
            return;
        }
    }

    if( cert_profile_list_.size() <= 0 )
    {
        manApplet->warningBox( tr( "There is no certificate profile"), this );
        return;
    }

    if( !bSelf )
    {
        if( ca_cert_list_.size() <= 0 )
        {
            manApplet->warningBox(tr("There is no CA certificate"), this );
            return;
        }
    }
    else
    {
        if( manApplet->isLicense() == false )
        {
            int nSelfCount = dbMgr->getCertCount( -1 );
            if( nSelfCount >= JS_NO_LICENSE_SELF_LIMIT_COUNT )
            {
                manApplet->warningBox(tr("You can not make more than %1 selfsign certificate in no license")
                                  .arg( JS_NO_LICENSE_SELF_LIMIT_COUNT ), this );
                return;
            }
        }
    }

    int reqIdx =  mReqNameCombo->currentIndex();
    int profileIdx = mProfileNameCombo->currentIndex();
    int issuerIdx = mIssuerNameCombo->currentIndex();

    int nSignKeyNum = -1;
    int nKeyType = -1;
    int nIssuerNum = -1;


    ReqRec reqRec;
    CertProfileRec profileRec = cert_profile_list_.at( profileIdx );
    if( mUseCSRFileCheck->isChecked() )
    {
        JS_BIN_fileRead( mCSRFilePathText->text().toLocal8Bit().toStdString().c_str(), &binCSR );
    }
    else
    {
        reqRec = req_list_.at( reqIdx );
        JS_BIN_decodeHex( reqRec.getCSR().toStdString().c_str(), &binCSR );
    }

    JS_PKI_getReqInfo( &binCSR, &sReqInfo, &pCSRExtInfoList );

    if( sReqInfo.bVerify == 0 )
    {
        manApplet->warningBox(tr("Request is not verified"), this );
        JS_PKI_resetReqInfo( &sReqInfo );
        JS_BIN_reset( &binCSR );
        return;
    }

    manApplet->log( QString( "PublicKey : %1").arg( sReqInfo.pPublicKey ));

    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
    JS_PKI_getKeyIdentifier( &binPub, &binKeyID );

    if( bSelf )
    {
        if( mUseCSRFileCheck->isChecked() )
        {
            manApplet->warningBox(tr("In case of using csr file, You can not make selfsign certificate."), this );
            JS_BIN_reset( &binCSR );
            JS_PKI_resetReqInfo( &sReqInfo );
            JS_BIN_reset( &binCSR );
            JS_BIN_reset( &binPub );

            return;
        }

        nSignKeyNum = reqRec.getKeyNum();
        JS_BIN_decodeHex( sReqInfo.pPublicKey, &binSignCert );
    }
    else {
        CertRec issuerCert = ca_cert_list_.at( issuerIdx );

        if( issuerCert.getStatus() == JS_CERT_STATUS_REVOKE )
        {
            QString strMsg = tr( "The CA certificate is revoked. continue?" );
            bool bVal = manApplet->yesOrNoBox( strMsg, NULL );
            if( bVal == false )
            {
                JS_BIN_reset( &binCSR );
                JS_PKI_resetReqInfo( &sReqInfo );
                JS_BIN_reset( &binCSR );
                JS_BIN_reset( &binPub );

                return;
            }
        }

        nSignKeyNum = issuerCert.getKeyNum();
        nIssuerNum = issuerCert.getNum();
        JS_BIN_decodeHex( issuerCert.getCert().toStdString().c_str(), &binSignCert );
    }

    QString strSerial;
    int nSeq = -1;
    QString strSignAlg;
    QString strDN;
    time_t now_t = -1;
    long notBefore = -1;
    long notAfter = -1;
    QList<ProfileExtRec> profileExtList;

    KeyPairRec signKeyPair;
    dbMgr->getKeyPairRec( nSignKeyNum, signKeyPair );

    if( signKeyPair.getParam() == "SM2" )
    {
        if( profileRec.getHash() != "SM3" )
        {
            QString strMsg = tr( "Profile Hash(%1) has to be SM3. Are you change certificate hash as SM3?" ).arg( profileRec.getHash());
            bool bVal = manApplet->yesOrNoBox( strMsg, this, true );

            if( bVal )
            {
                profileRec.setHash( "SM3" );
            }
            else
            {
                goto end;
            }
        }
    }
    else if( signKeyPair.getAlg() != kMechEdDSA )
    {
        if( profileRec.getHash() == "SM3" )
        {
            QString strMsg = tr( "Profile SM3 hash can not be used (%1:%2)" )
                    .arg( signKeyPair.getAlg() )
                    .arg( signKeyPair.getParam() );

            manApplet->warningBox( strMsg, this );
            goto end;
        }
    }

    /* need to work more */


    nSeq = dbMgr->getNextVal( "TB_CERT" );

    strSerial = QString("%1").arg(nSeq);
    strSignAlg = getSignAlg( signKeyPair.getAlg(), profileRec.getHash() );

    nKeyType = getKeyType( signKeyPair.getAlg(), signKeyPair.getParam() );
    strDN = getRealSubjectDN();
    now_t = time(NULL);



    if( profileRec.getNotBefore() == 0 )
    {
        long uValidSecs = profileRec.getNotAfter() * 60 * 60 * 24;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else if( profileRec.getNotBefore() == 1 )
    {
        long uValidSecs = profileRec.getNotAfter() * 60 * 60 * 24 * 30;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else if( profileRec.getNotBefore() == 2 )
    {
        long uValidSecs = profileRec.getNotAfter() * 60 * 60 * 24 * 365;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else
    {
        notBefore = profileRec.getNotBefore() - now_t;
        notAfter = profileRec.getNotAfter() - now_t;
    }



    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                        profileRec.getVersion(),
                        strSerial.toStdString().c_str(),
                        profileRec.getHash().toStdString().c_str(),
                        strDN.toStdString().c_str(),
                        notBefore,
                        notAfter,
                        sReqInfo.nKeyAlg,
                        sReqInfo.pPublicKey );

    /* need to support extensions start */

    dbMgr->getCertProfileExtensionList( profileRec.getNum(), profileExtList );
    for( int i=0; i < profileExtList.size(); i++ )
    {
        JExtensionInfo sExtInfo;
        ProfileExtRec profileExt = profileExtList.at(i);

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        if( profileExt.getSN() == JS_PKI_ExtNameBC )
        {
            QString strVal = profileExt.getValue();
            if( strVal.contains( "CA" ) == true )
                bCA = true;
            else
                bCA = false;
        }
        else if( profileExt.getSN() == JS_PKI_ExtNameSKI )
        {
            profileExt.setValue( getHexString( &binKeyID ) );
        }
        else if( profileExt.getSN() == JS_PKI_ExtNameCRLDP )
        {
            char *pDN = NULL;
            JS_PKI_getDP( profileExt.getValue().toStdString().c_str(), nSeq, &pDN );
            profileExt.setValue( pDN );
            if( pDN ) JS_free( pDN );
        }
        else if( profileExt.getSN() == JS_PKI_ExtNameSAN )
        {
            QString strAltName = profileExt.getValue();
            QString strReplace = getReplacedValue( strAltName );
            profileExt.setValue( strAltName );
        }
        else if( profileExt.getSN() == JS_PKI_ExtNameAKI )
        {
            if( bSelf == false )
            {
                BIN binCert = {0,0};
                char sHexID[256];
                char sHexSerial[256];
                char sHexIssuer[1024];

                memset( sHexID, 0x00, sizeof(sHexID) );
                memset( sHexSerial, 0x00, sizeof(sHexSerial) );
                memset( sHexIssuer, 0x00, sizeof(sHexIssuer) );


                CertRec issuerCert = ca_cert_list_.at( issuerIdx );
                JS_BIN_decodeHex( issuerCert.getCert().toStdString().c_str(), &binCert );

                JS_PKI_getAuthorityKeyIdentifier( &binCert, sHexID, sHexSerial, sHexIssuer );
                QString strVal = QString( "KEYID$%1").arg( sHexID );

                if( profileExt.getValue().contains( "ISSUER" ) )
                    strVal += QString( "#ISSUER$%1" ).arg( sHexIssuer );

                if( profileExt.getValue().contains( "SERIAL" ) )
                    strVal += QString( "#SERIAL$%1").arg( sHexSerial );

                profileExt.setValue( strVal );

                JS_BIN_reset( &binCert );
            }
            else
            {
                /* SelfSign 경우 KeyID 만 설정. */
                QString strVal = QString( "KEYID$%1").arg( getHexString( &binKeyID ) );
                profileExt.setValue( strVal );
                /*
                Need to support ISSUER and SERIAL
                */
            }
        }

        transExtInfoFromDBRec( &sExtInfo, profileExt );
        JS_PKI_addExtensionInfoList( &pCertExtInfoList, &sExtInfo );
    }
    /* need to support extensions end */

    JS_PKI_getExtensionUsageList( profileRec.getExtUsage(), pCertExtInfoList, pCSRExtInfoList, &pExtInfoList );

    if( bCA && manApplet->isLicense() == false)
    {
        int nCACnt = dbMgr->getCACount();
        if( nCACnt >= JS_NO_LICENSE_CA_LIMIT_COUNT )
        {
            manApplet->warningBox(tr("You can not make more than %1 CA certificates in no license")
                                  .arg( JS_NO_LICENSE_CA_LIMIT_COUNT), this );
            ret = -1;
            goto end;
        }
    }

    if( signKeyPair.getAlg() == kMechPKCS11_RSA || signKeyPair.getAlg() == kMechPKCS11_EC || signKeyPair.getAlg() == kMechPKCS11_DSA )
    {
        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();
        BIN binID = {0,0};

        CK_SESSION_HANDLE hSession = getP11Session( pP11CTX, nSlotID, strPIN );
        if( hSession < 0 )
        {
            goto end;
        }

        JS_BIN_decodeHex( signKeyPair.getPrivateKey().toStdString().c_str(), &binID  );

        ret = JS_PKI_makeCertificateByP11( bSelf, &sIssueCertInfo, pExtInfoList, &binID, &binSignCert, pP11CTX, &binCert );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
        JS_BIN_reset( &binID );
    }
    else if( signKeyPair.getAlg() == kMechKMIP_RSA || signKeyPair.getAlg() == kMechKMIP_EC )
    {
        if( manApplet->settingsMgr()->KMIPUse() == 0 )
            goto end;

        SSL_CTX *pCTX = NULL;
        SSL *pSSL = NULL;
        Authentication  *pAuth = NULL;
        BIN binID = {0,0};

        JS_BIN_decodeHex( signKeyPair.getPrivateKey().toStdString().c_str(), &binID  );

        ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );

        if( ret == 0 )
        {
            ret = JS_PKI_makeCertificateByKMIP( bSelf, &sIssueCertInfo, pExtInfoList, &binID, &binSignCert, (void *)pSSL, pAuth, &binCert );
        }

        if( pSSL ) JS_SSL_clear( pSSL );
        if( pCTX ) JS_SSL_finish( &pCTX );
        if( pAuth )
        {
            JS_KMS_resetAuthentication( pAuth );
            JS_free( pAuth );
        }
        JS_BIN_reset( &binID );
    }
    else
    {
        if( manApplet->isPasswd() )
            manApplet->getDecPriBIN( signKeyPair.getPrivateKey(), &binSignPri );
        else
            JS_BIN_decodeHex( signKeyPair.getPrivateKey().toStdString().c_str(), &binSignPri );

        ret = JS_PKI_makeCertificate( bSelf, &sIssueCertInfo, pExtInfoList, nKeyType, &binSignPri, &binSignCert, &binCert );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to make certificate(%1)").arg(ret), this );
        goto end;

    }

    ret = JS_PKI_getCertInfo( &binCert, &sMadeCertInfo, &pMadeExtInfoList );
    if( ret != 0 )
    {
        manApplet->warningBox(tr("fail to get certificate information(%1)").arg(ret), this );
        goto end;
    }

    JS_PKI_getExtensionValue( pMadeExtInfoList, JS_PKI_ExtNameCRLDP, &pHexCRLDP );
    if( pHexCRLDP ) JS_PKI_getExtensionStringValue( pHexCRLDP, JS_PKI_ExtNameCRLDP, &pCRLDP );

    JS_BIN_encodeHex( &binCert, &pHexCert );

    madeCertRec.setSelf( bSelf );
    madeCertRec.setStatus(JS_CERT_STATUS_GOOD);
    madeCertRec.setSignAlg( sMadeCertInfo.pSignAlgorithm );
    madeCertRec.setCert( pHexCert );

    ba = sMadeCertInfo.pSubjectName;
    madeCertRec.setSubjectDN( codec->toUnicode( ba ) );

    madeCertRec.setNum( nSeq );

    madeCertRec.setRegTime( now_t );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );
    madeCertRec.setKeyNum( reqRec.getKeyNum() );
    madeCertRec.setCA( bCA );
    madeCertRec.setIssuerNum( nIssuerNum );
    madeCertRec.setSerial( sMadeCertInfo.pSerial );
    madeCertRec.setDNHash( sMadeCertInfo.pDNHash );
    if( pCRLDP ) madeCertRec.setCRLDP( pCRLDP );
    JS_BIN_decodeHex( sMadeCertInfo.pPublicKey, &binPub );
    madeCertRec.setKeyHash( getHexString( &binKeyID ) );

    ret = dbMgr->addCertRec( madeCertRec );
    if( ret != 0 ) goto end;

    dbMgr->modReqStatus( reqRec.getSeq(), 1 );

    if( manApplet->isPRO() )
    {
        userRec.setName( mUserNameText->text() );
        userRec.setSSN( mSSNText->text() );
        userRec.setEmail( mEmailText->text() );
        userRec.setRegTime( time(NULL));
        userRec.setStatus( JS_USER_STATUS_REGISTER );
        if( userRec.getName().length() > 0 ) dbMgr->addUserRec( userRec );

        addAudit( dbMgr, JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_CERT, sMadeCertInfo.pSubjectName );
    }

    if( madeCertRec.isCA() && madeCertRec.isSelf() )
        manApplet->mainWindow()->addRootCA( madeCertRec );        

end :
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binSignPri );
    JS_BIN_reset(&binSignCert);
    JS_BIN_reset(&binCSR);
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_PKI_resetCertInfo( &sMadeCertInfo );
    if( pHexCert ) JS_free( pHexCert );
    if( pCertExtInfoList ) JS_PKI_resetExtensionInfoList( &pCertExtInfoList );
    if( pCSRExtInfoList ) JS_PKI_resetExtensionInfoList( &pCSRExtInfoList );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pMadeExtInfoList ) JS_PKI_resetExtensionInfoList( &pMadeExtInfoList );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binKeyID );
    JS_PKI_resetReqInfo( &sReqInfo );
    if( pHexCRLDP ) JS_free( pHexCRLDP );
    if( pCRLDP ) JS_free( pCRLDP );

    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightCertList( nIssuerNum );
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "fail to make certificate" ), this );
        QDialog::reject();
    }
}

void MakeCertDlg::reqChanged( int index )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ReqRec reqRec = req_list_.at(index);

    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( reqRec.getKeyNum(), keyPair );

    mAlgorithmText->setText( keyPair.getAlg() );
    mOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::issuerChanged( int index )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec certRec = ca_cert_list_.at(index);
    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mIssuerAlgorithmText->setText( keyPair.getAlg() );
    mIssuerOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::profileChanged(int index )
{
    setSubjectDN();
}

void MakeCertDlg::clickSelfSign()
{
    bool bStatus = mSelfSignCheck->isChecked();

    if( bStatus )
    {
        if( mUseCSRFileCheck->isChecked() )
        {
            manApplet->warningBox( tr("can not check selfsign when use csr file"), this );
            mSelfSignCheck->setChecked(false);
            return;
        }
    }
/*
    mIssuerNameCombo->setEnabled( !bStatus );
    mIssuerAlgorithmText->setEnabled( !bStatus );
    mIssuerOptionText->setEnabled( !bStatus );
*/

    mSelfSignLabel->setEnabled( bStatus );
    mIssuerGroup->setEnabled( !bStatus );
}

void MakeCertDlg::clickUseCSRFile()
{
    bool bVal = mUseCSRFileCheck->isChecked();

    mCSRFilePathText->setEnabled(bVal);
    mCSRFileFindBtn->setEnabled(bVal);
    mReqNameCombo->setEnabled(!bVal);
    mAlgorithmText->setEnabled(!bVal);
    mAlgorithmLabel->setEnabled(!bVal);
    mOptionLabel->setEnabled(!bVal);
    mOptionText->setEnabled(!bVal);

    if( mSelfSignCheck->isChecked() )
        mSelfSignCheck->setChecked( false );

    mSelfSignCheck->setDisabled( bVal );
}

void MakeCertDlg::findCSRFile()
{
    int ret = 0;
    int nType = JS_FILE_TYPE_BER;
    QString strPath;
    BIN binCSR = {0,0};
    JReqInfo    sReqInfo;

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    QString filePath = findFile( this, nType, strPath );
    if( filePath.length() > 0 )
    {
        ret = JS_BIN_fileRead( filePath.toLocal8Bit().toStdString().c_str(), &binCSR );
        if( ret != 0 ) goto end;

        ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, NULL );
        if( ret != 0 ) goto end;

        mCSRFilePathText->setText( filePath );
    }

end :
    JS_PKI_resetReqInfo( &sReqInfo );
    JS_BIN_reset( &binCSR );
}
