/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
//#include <QtCore5Compat/QTextCodec>

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
#include "make_dn_dlg.h"
#include "ca_man_dlg.h"
#include "profile_man_dlg.h"

#include "js_gen.h"
#include "js_kms.h"
#include "js_define.h"


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

    connect( mReqNumText, SIGNAL(textChanged(QString)), this, SLOT(reqNumChanged()));
    connect( mIssuerNumText, SIGNAL(textChanged(QString)), this, SLOT(issuerNumChanged()));
    connect( mProfileNumText, SIGNAL(textChanged(QString)), this, SLOT(profileNumChanged()));
    connect( mSelfSignCheck, SIGNAL(clicked()), this, SLOT(clickSelfSign()));
    connect( mUseCSRFileCheck, SIGNAL(clicked()), this, SLOT(clickUseCSRFile()));
    connect( mCSRFileFindBtn, SIGNAL(clicked()), this, SLOT(findCSRFile()));
    connect( mMakeDNBtn, SIGNAL(clicked()), this, SLOT(clickMakeDN()));

    connect( mSelectCSRBtn, SIGNAL(clicked()), this, SLOT(clickSelectCSR()));
    connect( mSelectProfileBtn, SIGNAL(clicked()), this, SLOT(clickSelectProfile()));
    connect( mSelectCACertBtn, SIGNAL(clicked()), this, SLOT(clickSelectCACert()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    if( manApplet->isPRO() == false )
    {
        mUserGroup->hide();
        resize( width(), height() - 120 );
    }

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeCertDlg::~MakeCertDlg()
{

}

void MakeCertDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void MakeCertDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( manApplet->settingsMgr()->issuerNum() > 0 )
        mIssuerNumText->setText( QString("%1").arg( manApplet->settingsMgr()->issuerNum() ));

    if( manApplet->settingsMgr()->certProfileNum() > 0 )
        mProfileNumText->setText( QString( "%1").arg( manApplet->settingsMgr()->certProfileNum() ));

    setSubjectDN();
    clickUseCSRFile();
}

void MakeCertDlg::setSubjectDN()
{
    int nNum = mProfileNumText->text().toInt();
    CertProfileRec   profile;
    manApplet->dbMgr()->getCertProfileRec( nNum, profile );

    if( profile.getDNTemplate() == kCSR_DN && mUseCSRFileCheck->isChecked() == false )
    {
        int nReqNum = mReqNumText->text().toInt();
        ReqRec req;
        manApplet->dbMgr()->getReqRec( nReqNum, req );
        mSubjectDNText->setText( req.getDN() );
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

void MakeCertDlg::setIssuer( int nCertNum )
{
    mIssuerNumText->setText( QString("%1").arg( nCertNum ) );
}

void MakeCertDlg::setReqNum( int nReqNum )
{
    if( nReqNum < 0 ) return;

    mReqNumText->setText( QString( "%1" ).arg( nReqNum ));
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

    UserRec userRec;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    bool bSelf = mSelfSignCheck->isChecked();

    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sMadeCertInfo, 0x00, sizeof(sMadeCertInfo));
    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    ReqRec reqRec;
    QString strReqNum;
    QString strProfileNum;
    QString strIssuerNum;

    if( mUseCSRFileCheck->isChecked() )
    {
        if( mCSRFilePathText->text().length() <= 0 )
        {
            manApplet->warningBox( tr( "Find a CSR file"), this );
            mCSRFilePathText->setFocus();
            return;
        }
    }
    else
    {
        if( mReqNumText->text().length() < 1 )
        {
            clickSelectCSR();
            if( mReqNumText->text().length() < 1 )
            {
                manApplet->warningBox( tr( "Select a CSR" ), this );
                return;
            }
        }

        strReqNum = mReqNumText->text();

        if( mProfileNumText->text().length() < 1 )
        {
            clickSelectProfile();
            if( mProfileNumText->text().length() < 1 )
            {
                manApplet->warningBox( tr( "Select a profile" ), this );
                return;
            }
        }

        strProfileNum = mProfileNumText->text();

        if( bSelf == false )
        {
            if( mIssuerNumText->text().length() < 1 )
            {
                clickSelectCACert();
                if( mIssuerNumText->text().length() < 1 )
                {
                    manApplet->warningBox( tr( "Select a CA certificate" ), this );
                    return;
                }
            }

            strIssuerNum = mIssuerNumText->text();
        }
    }

    int profileIdx = strProfileNum.toInt();
    int issuerIdx = strIssuerNum.toInt();

    int nSignKeyNum = -1;
    int nKeyType = -1;
    int nIssuerNum = -1;

    CertProfileRec profileRec;
    dbMgr->getCertProfileRec( profileIdx, profileRec );
    if( mUseCSRFileCheck->isChecked() )
    {
        JS_BIN_fileReadBER( mCSRFilePathText->text().toLocal8Bit().toStdString().c_str(), &binCSR );
        ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, 0, &pCSRExtInfoList );

        if( ret != 0 )
        {
            manApplet->warningBox( tr( "Invalid CSR file [%1]" ).arg( ret ), this);
            return;
        }

        if( mSubjectDNText->text() == kCSR_DN )
            mSubjectDNText->setText( sReqInfo.pSubjectDN );

        if( mSaveToRequestCheck->isChecked() )
        {
            reqRec.setCSR( getHexString( &binCSR ));
            reqRec.setRegTime( time(NULL) );
            reqRec.setDN( sReqInfo.pSubjectDN );
            reqRec.setHash( sReqInfo.pSignAlgorithm );
            reqRec.setName( QString( "[I] %1" ).arg(sReqInfo.pSubjectDN) );

            dbMgr->addReqRec( reqRec );
        }
    }
    else
    {
        int reqIdx =  strReqNum.toInt();
        dbMgr->getReqRec( reqIdx, reqRec );
        JS_BIN_decodeHex( reqRec.getCSR().toStdString().c_str(), &binCSR );
        ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, 0, &pCSRExtInfoList );

        if( ret != 0 )
        {
            manApplet->warningBox( tr( "Invalid CSR file [%1]" ).arg( ret ), this);
            return;
        }
    }


    if( sReqInfo.bVerify == 0 )
    {
        manApplet->warningBox(tr("CSR verification failed"), this );
        JS_PKI_resetReqInfo( &sReqInfo );
        JS_BIN_reset( &binCSR );
        return;
    }

    manApplet->log( QString( "PublicKey : %1").arg( sReqInfo.pPublicKey ));

    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
    // Need to check EdDSA identifer
    ret = JS_PKI_getKeyIdentifier( &binPub, &binKeyID );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to get KeyIdentifier: %1").arg( ret ));
        return;
    }

    if( bSelf )
    {
        if( mUseCSRFileCheck->isChecked() )
        {
            manApplet->warningBox(tr("You cannot create a Self-Sign certificate using CSR"), this );
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
        CertRec issuerCert;
        dbMgr->getCertRec( issuerIdx, issuerCert );

        if( issuerCert.getStatus() == JS_CERT_STATUS_REVOKE )
        {
            QString strMsg = tr( "The CA certificate has been revoked. continue?" );
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
            QString strMsg = tr( "The hash(%1) in the profile is not SM3. Would you like to change to SM3?" ).arg( profileRec.getHash());
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
            QString strMsg = tr( "SM3 hash cannot be used in profiles (%1:%2)" )
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


    if( nKeyType != sReqInfo.nKeyAlg )
    {
        bool bVal = manApplet->yesOrNoBox( tr( "CSR KeyAlg[%1] and SignKey Alg[%2] are different. Continue?" )
                                           .arg( JS_PKI_getKeyTypeName( sReqInfo.nKeyAlg ) )
                                           .arg( JS_PKI_getKeyTypeName( nKeyType )), this, false );
        if( bVal == false )
        {
            ret = -1;
            goto end;
        }
    }

    if( profileRec.getNotBefore() == kPeriodDay )
    {
        long uValidSecs = profileRec.getNotAfter() * 60 * 60 * 24;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else if( profileRec.getNotBefore() == kPeriodMonth )
    {
        long uValidSecs = profileRec.getNotAfter() * 60 * 60 * 24 * 30;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else if( profileRec.getNotBefore() == kPeriodYear )
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


                CertRec issuerCert;
                dbMgr->getCertRec( issuerIdx, issuerCert );
                JS_BIN_decodeHex( issuerCert.getCert().toStdString().c_str(), &binCert );

                ret = JS_PKI_getAuthorityKeyIdentifier( &binCert, sHexID, sHexSerial, sHexIssuer );
                if( ret != 0 )
                {
                    manApplet->elog( QString( "failed to get AuthorityKeyIdentifier: %1").arg( ret ));
                    JS_BIN_reset( &binCert );
                    goto end;
                }

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

    if( isPKCS11Private( signKeyPair.getAlg() ) == true )
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
    else if( isKMIPPrivate( signKeyPair.getAlg() ) == true )
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

        manApplet->getPriKey( signKeyPair.getPrivateKey(), &binSignPri );

        ret = JS_PKI_makeCertificate( bSelf, &sIssueCertInfo, pExtInfoList, &binSignPri, &binSignCert, &binCert );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to make certificate [%1]").arg(ret), this );
        goto end;

    }

    ret = JS_PKI_getCertInfo( &binCert, &sMadeCertInfo, &pMadeExtInfoList );
    if( ret != 0 )
    {
        manApplet->warningBox(tr("failed to get certificate information [%1]").arg(ret), this );
        goto end;
    }

    JS_PKI_getExtensionValue( pMadeExtInfoList, JS_PKI_ExtNameCRLDP, &pHexCRLDP );
    if( pHexCRLDP ) JS_PKI_getExtensionStringValue( pHexCRLDP, JS_PKI_ExtNameCRLDP, &pCRLDP );

    JS_BIN_encodeHex( &binCert, &pHexCert );

    madeCertRec.setSelf( bSelf );
    madeCertRec.setStatus(JS_CERT_STATUS_GOOD);
    madeCertRec.setSignAlg( sMadeCertInfo.pSignAlgorithm );
    madeCertRec.setCert( pHexCert );

 //   ba = sMadeCertInfo.pSubjectName;
 //   madeCertRec.setSubjectDN( codec->toUnicode( ba ) );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );

    madeCertRec.setNum( nSeq );

    madeCertRec.setRegTime( now_t );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );
    madeCertRec.setKeyNum( reqRec.getKeyNum() );
    madeCertRec.setCA( bCA );
    madeCertRec.setIssuerNum( nIssuerNum );
    madeCertRec.setSerial( sMadeCertInfo.pSerial );
    madeCertRec.setDNHash( sMadeCertInfo.pDNHash );
    if( pCRLDP )
    {
        QString strFirstCRLDP = getCRLDPFromInfo( pCRLDP );
        madeCertRec.setCRLDP( strFirstCRLDP );
    }

    JS_BIN_decodeHex( sMadeCertInfo.pPublicKey, &binPub );
    madeCertRec.setKeyHash( getHexString( &binKeyID ) );

    ret = dbMgr->addCertRec( madeCertRec );
    if( ret != 0 ) goto end;

    if( reqRec.getSeq() > 0 ) dbMgr->modReqStatus( reqRec.getSeq(), 1 );

    if( manApplet->isPRO() )
    {
        userRec.setName( mUserNameText->text() );
        userRec.setSSN( mSSNText->text() );
        userRec.setEmail( mEmailText->text() );
        userRec.setRegTime( time(NULL));
        userRec.setStatus( JS_USER_STATUS_REGISTER );
        if( userRec.getName().length() > 0 )
        {
            dbMgr->addUserRec( userRec );
            addAudit( dbMgr, JS_GEN_KIND_CERTMAN, JS_GEN_OP_REG_USER, "" );
        }

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
        manApplet->settingsMgr()->setCertProfileNum( mProfileNumText->text().toInt() );
        if( bSelf == false ) manApplet->settingsMgr()->setIssuerNum( mIssuerNumText->text().toInt() );

        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "failed to make certificate [%1]" ).arg(ret), this );
        QDialog::reject();
    }
}

void MakeCertDlg::reqNumChanged()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    int nNum = mReqNumText->text().toInt();

    ReqRec reqRec;
    int ret = manApplet->dbMgr()->getReqRec( nNum, reqRec );
    if( ret != 0 )
    {
        mReqNumText->clear();
        return;
    }

    mReqNameText->setText( reqRec.getName() );

    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( reqRec.getKeyNum(), keyPair );

    mAlgorithmText->setText( keyPair.getAlg() );
    mOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::issuerNumChanged()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int nNum = mIssuerNumText->text().toInt();

    CertRec certRec;
    KeyPairRec keyPair;

    int ret = dbMgr->getCertRec( nNum, certRec );
    if( ret != 0 )
    {
        mIssuerNumText->clear();
        return;
    }

    mIssuerNameText->setText( certRec.getSubjectDN() );

    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mIssuerAlgorithmText->setText( keyPair.getAlg() );
    mIssuerOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::profileNumChanged()
{
    int nNum = mProfileNumText->text().toInt();
    CertProfileRec profile;
    int ret = manApplet->dbMgr()->getCertProfileRec( nNum, profile );
    if( ret != 0 )
    {
        mProfileNumText->clear();
        return;
    }

    mProfileNameText->setText( profile.getName() );

    setSubjectDN();
}

void MakeCertDlg::clickSelfSign()
{
    bool bStatus = mSelfSignCheck->isChecked();

    if( bStatus )
    {
        if( mUseCSRFileCheck->isChecked() )
        {
            manApplet->warningBox( tr("You cannot create a Self-Sign certificate using CSR"), this );
            mSelfSignCheck->setChecked(false);
            return;
        }
    }

    mSelfSignLabel->setEnabled( bStatus );
    mIssuerGroup->setEnabled( !bStatus );
}

void MakeCertDlg::clickUseCSRFile()
{
    bool bVal = mUseCSRFileCheck->isChecked();

    mSaveToRequestCheck->setEnabled( bVal );

    mCSRFilePathText->setEnabled(bVal);
    mCSRFileFindBtn->setEnabled(bVal);
    mReqNameText->setEnabled(!bVal);
    mReqNumText->setEnabled(!bVal);
    mAlgorithmText->setEnabled(!bVal);
    mAlgorithmLabel->setEnabled(!bVal);
    mOptionLabel->setEnabled(!bVal);
    mOptionText->setEnabled(!bVal);

    if( mSelfSignCheck->isChecked() )
        mSelfSignCheck->setChecked( false );

    mSelfSignCheck->setDisabled( bVal );
    setSubjectDN();
}

void MakeCertDlg::findCSRFile()
{
    int ret = 0;
    int nType = JS_FILE_TYPE_BER;
    QString strPath;
    BIN binCSR = {0,0};
    JReqInfo    sReqInfo;

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    strPath = mCSRFilePathText->text();
    strPath = manApplet->curPath(strPath);

    QString filePath = findFile( this, nType, strPath );
    if( filePath.length() > 0 )
    {
        ret = JS_BIN_fileReadBER( filePath.toLocal8Bit().toStdString().c_str(), &binCSR );
        if( ret <= 0 ) goto end;

        ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, 1, NULL );
        if( ret != 0 ) goto end;

        mCSRFilePathText->setText( filePath );
        mSubjectDNText->setText( sReqInfo.pSubjectDN );
    }

end :
    JS_PKI_resetReqInfo( &sReqInfo );
    JS_BIN_reset( &binCSR );
}

void MakeCertDlg::clickMakeDN()
{
    QString strDN = mSubjectDNText->text();

    MakeDNDlg makeDNDlg;
    makeDNDlg.setDN( strDN );

    if( makeDNDlg.exec() == QDialog::Accepted )
    {
        strDN = makeDNDlg.getDN();
        mSubjectDNText->setText( strDN );
    }
}

void MakeCertDlg::clickSelectCSR()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select CSR" ));
    caMan.setMode( CAManModeSelectCSR );

    if( caMan.exec() == QDialog::Accepted )
    {
        mReqNumText->setText( QString("%1").arg( caMan.getNum() ));
    }
}

void MakeCertDlg::clickSelectProfile()
{
    ProfileManDlg profileMan;
    profileMan.setTitle( tr( "Select a profile" ));
    profileMan.setMode( ProfileManModeSelectCertProfile );

    if( profileMan.exec() == QDialog::Accepted )
    {
        mProfileNumText->setText( QString("%1").arg( profileMan.getNum() ));
    }
}

void MakeCertDlg::clickSelectCACert()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select CA certificate" ));
    caMan.setMode( CAManModeSelectCACert );

    if( caMan.exec() == QDialog::Accepted )
    {
        mIssuerNumText->setText(QString("%1").arg( caMan.getNum() ));
    }
}
