#include "js_gen.h"

#include "renew_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"
#include "settings_mgr.h"
#include "js_pki_x509.h"
#include "js_define.h"
#include "commons.h"

static QStringList kPeriodTypes = { "Day", "Month", "Year" };

RenewCertDlg::RenewCertDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    is_self_ = false;

    connect( mDayTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeDayType(int)));
    connect( mUseDayCheck, SIGNAL(clicked()), this, SLOT(clickUseDay()));
    connect( mKeepSerialCheck, SIGNAL(clicked()), this, SLOT(clickKeepSerial()));
    connect( mRevokeCheck, SIGNAL(clicked()), this, SLOT(clickRevoke()));

    initialize();
}

RenewCertDlg::~RenewCertDlg()
{

}

void RenewCertDlg::setCertNum(int cert_num)
{
    cert_num_ = cert_num;
}

void RenewCertDlg::initialize()
{
    mDayTypeCombo->addItems( kPeriodTypes );
    mRevokeReasonCombo->addItems( kRevokeReasonList );
    mRevokeReasonCombo->setCurrentText("superseded");
    mRevokeCheck->setChecked(true);
    clickUseDay();
    clickRevoke();
}

void RenewCertDlg::showEvent(QShowEvent *event)
{
    CertRec cert;
    CertRec caCert;
    KeyPairRec keyPair;
    int nKeyNum = -1;
    JCertInfo sCertInfo;
    BIN binCert = {0,0};
    QDateTime startDateTime;
    QDateTime endDateTime;

    DBMgr* dbMgr = manApplet->dbMgr();
    QString strSerial;


    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    dbMgr->getCertRec( cert_num_, cert );

    if( cert.isSelf() )
    {
        nKeyNum = cert.getKeyNum();
        is_self_ = true;
        mRevokeCheck->setEnabled( false );
        mRevokeReasonCombo->setEnabled( false );
    }
    else
    {
        dbMgr->getCertRec( cert.getIssuerNum(), caCert );
        nKeyNum = caCert.getKeyNum();

        if( caCert.getKeyNum() <= 0 )
        {
            manApplet->elog( QString("Key Num is wrong").arg( caCert.getKeyNum() ));
            return;
        }
        is_self_ = false;
        mRevokeCheck->setEnabled( true );
        mRevokeReasonCombo->setEnabled( true );
    }

    dbMgr->getKeyPairRec( nKeyNum, keyPair );
    JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    startDateTime.setSecsSinceEpoch( sCertInfo.uNotBefore );
    endDateTime.setSecsSinceEpoch( sCertInfo.uNotAfter );

    mNotBeforeText->setText( startDateTime.toString( "yyyy-MM-dd HH:mm:ss" ) );
    mNotAfterText->setText( endDateTime.toString( "yyyy-MM-dd HH:mm:ss" ));

    mNotBeforeDateTime->setDateTime( startDateTime );
    mNotAfterDateTime->setDateTime( endDateTime );

    mCertDNText->setText( cert.getSubjectDN() );
    mSignKeyName->setText( keyPair.getName() );
    mSerialText->setText( sCertInfo.pSerial );

    JS_PKI_resetCertInfo( &sCertInfo );
    JS_BIN_reset( &binCert );
}

void RenewCertDlg::accept()
{
    int ret = 0;
    CertRec cert;
    CertRec caCert;
    CertRec madeCertRec;
    KeyPairRec keyPair;
    int nKeyNum = -1;
    JCertInfo sCertInfo;
    JCertInfo sMadeCertInfo;
    BIN binCert = {0,0};
    BIN binRenewCert = {0,0};
    BIN binID = {0,0};
    BIN binSignPri = {0,0};
    BIN binSignCert = {0,0};

    time_t now_t = time(NULL);
    long notBefore = -1;
    long notAfter = -1;
    const char *pSerial = NULL;
    QString strKeyAlg;

//    int nKeyType = -1;
    int nRenewCertNum = -1;
    long uLimitBefore = -1;
    long uLimitAfter = -1;

//    QTextCodec *codec = QTextCodec::codecForName("UTF-16");
//    QByteArray ba;

    DBMgr* dbMgr = manApplet->dbMgr();
    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    memset( &sMadeCertInfo, 0x00, sizeof(sMadeCertInfo));
/*
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
*/

    dbMgr->getCertRec( cert_num_, cert );

/*
    if( cert.isCA() && manApplet->isLicense() == false )
    {
        int nCACnt = dbMgr->getCACount();
        if( nCACnt >= JS_NO_LICENSE_CA_LIMIT_COUNT )
        {
            manApplet->warningBox(tr("You can not make more than %1 CA certificates in no license")
                                  .arg( JS_NO_LICENSE_CA_LIMIT_COUNT), this );

            return;
        }
    }
*/

    if( cert.isSelf() )
    {
/*
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
*/

        nKeyNum = cert.getKeyNum();
        JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binSignCert );
    }
    else
    {
        JCertInfo sSignInfo;
        memset( &sSignInfo, 0x00, sizeof(sSignInfo));

        dbMgr->getCertRec( cert.getIssuerNum(), caCert );
        nKeyNum = caCert.getKeyNum();

        if( caCert.getKeyNum() <= 0 )
        {
            manApplet->elog( QString("Key Num is wrong").arg( caCert.getKeyNum() ));
            return;
        }

        JS_BIN_decodeHex( caCert.getCert().toStdString().c_str(), &binSignCert );
        JS_PKI_getCertInfo( &binSignCert, &sSignInfo, NULL );

        uLimitBefore = sSignInfo.uNotBefore;
        uLimitAfter = sSignInfo.uNotAfter;

        JS_PKI_resetCertInfo( &sSignInfo );
    }

    dbMgr->getKeyPairRec( nKeyNum, keyPair );
    JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );


    if( mUseDayCheck->isChecked() )
    {
        long uSecs = 0;
        notBefore = 0;

        if( mDayTypeCombo->currentText() == "Day" )
            uSecs = 60 * 60 * 24;
        else if( mDayTypeCombo->currentText() == "Month" )
            uSecs = 60 * 60 * 24 * 30;
        else if( mDayTypeCombo->currentText() == "Year" )
            uSecs = 60 * 60 * 24 * 365;

        notAfter = uSecs * mDayText->text().toInt();
    }
    else
    {
        notBefore = mNotBeforeDateTime->dateTime().toSecsSinceEpoch() - now_t;
        notAfter = mNotAfterDateTime->dateTime().toSecsSinceEpoch() - now_t;
    }

    if( uLimitBefore > 0 )
    {
        if( uLimitBefore > ( notBefore + now_t ) )
        {
            QDateTime limitDateTime;
            QDateTime beforeDateTime;

            limitDateTime.setSecsSinceEpoch( uLimitBefore );
            beforeDateTime.setSecsSinceEpoch( notBefore + now_t );

            QString strErr = tr("It(%1) cannot be earlier than issuer time(%2).")
                    .arg( beforeDateTime.toString( "yyyy-MM-dd HH:mm:ss"))
                    .arg( limitDateTime.toString( "yyyy-MM-dd HH:mm:ss") );

            manApplet->elog( strErr );
            manApplet->warningBox( strErr, this );
            ret = -1;
            goto end;
        }
    }

    if( uLimitAfter > 0 )
    {
        if( uLimitAfter < ( notAfter + now_t ) )
        {
            QDateTime limitDateTime;
            QDateTime afterDateTime;

            limitDateTime.setSecsSinceEpoch( uLimitBefore );
            afterDateTime.setSecsSinceEpoch( notAfter + now_t );

            QString strErr = tr("It(%1) cannot be later than the issuer time(%2).")
                    .arg( afterDateTime.toString( "yyyy-MM-dd HH:mm:ss"))
                    .arg( limitDateTime.toString( "yyyy-MM-dd HH:mm:ss") );

            manApplet->elog( strErr );
            manApplet->warningBox( strErr, this );

            ret = -1;
            goto end;
        }
    }
\
    if( mSerialText->text().length() > 0 )
        pSerial = mSerialText->text().toStdString().c_str();

    strKeyAlg = keyPair.getAlg();

//    nKeyType = getKeyType( strKeyAlg, keyPair.getParam() );

    if( strKeyAlg == kMechPKCS11_RSA || strKeyAlg == kMechPKCS11_EC || strKeyAlg == kMechPKCS11_DSA )
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

        JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binID  );

        ret = JS_PKI_renewCertificateByP11( &binCert, &binSignCert, &binID, pP11CTX, notBefore, notAfter, pSerial, &binRenewCert );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
        JS_BIN_reset( &binID );
    }
    else if( strKeyAlg == kMechKMIP_RSA || strKeyAlg == kMechKMIP_EC )
    {
        if( manApplet->settingsMgr()->KMIPUse() == 0 )
            goto end;

        SSL_CTX *pCTX = NULL;
        SSL *pSSL = NULL;
        Authentication  *pAuth = NULL;
        BIN binID = {0,0};

        JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binID  );

        ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );

        if( ret == 0 )
        {
            ret = JS_PKI_renewCertificateByKMIP( &binCert, &binSignCert, &binID, pSSL, pAuth, notBefore, notAfter, pSerial, &binRenewCert );
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
            manApplet->getDecPriBIN( keyPair.getPrivateKey(), &binSignPri );
        else
            JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binSignPri );

        ret = JS_PKI_renewCertificate( &binCert, &binSignPri, notBefore, notAfter, pSerial, &binRenewCert );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to make certificate(%1)").arg(ret), this );
        goto end;

    }

    ret = JS_PKI_getCertInfo( &binRenewCert, &sMadeCertInfo, NULL );
    if( ret != 0 )
    {
        manApplet->warningBox(tr("fail to get certificate information(%1)").arg(ret), this );
        goto end;
    }

    madeCertRec.setSelf( cert.isSelf() );
    madeCertRec.setStatus(JS_CERT_STATUS_GOOD);
    madeCertRec.setSignAlg( sMadeCertInfo.pSignAlgorithm );
    madeCertRec.setCert( getHexString( &binRenewCert) );

//    ba = sMadeCertInfo.pSubjectName;
//    madeCertRec.setSubjectDN( codec->toUnicode( ba ) );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );

    nRenewCertNum = dbMgr->getNextVal( "TB_CERT" );
    madeCertRec.setNum( nRenewCertNum );

    madeCertRec.setRegTime( now_t );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );
    madeCertRec.setKeyNum( nKeyNum );
    madeCertRec.setCA( cert.isCA() );
    madeCertRec.setIssuerNum( cert.getIssuerNum() );
    madeCertRec.setSerial( sMadeCertInfo.pSerial );
    madeCertRec.setDNHash( sMadeCertInfo.pDNHash );
    madeCertRec.setCRLDP( cert.getCRLDP() );
    madeCertRec.setKeyHash( cert.getKeyHash() );

    dbMgr->addCertRec( madeCertRec );

    if( mRevokeCheck->isChecked() )
    {
        int nReason = mRevokeReasonCombo->currentIndex();

        RevokeRec revoke;
        revoke.setCertNum( cert_num_ );
        revoke.setIssuerNum( cert.getIssuerNum() );
        revoke.setSerial( QString("%1").arg(cert.getNum()));
        revoke.setReason( nReason );
        revoke.setRevokeDate( QDateTime::currentDateTime().toSecsSinceEpoch() );
        revoke.setCRLDP( cert.getCRLDP() );

        dbMgr->addRevokeRec( revoke );
        dbMgr->modCertStatus( cert_num_, JS_CERT_STATUS_REVOKE );

        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_REVOKE_CERT, "" );

    }

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_RENEW_CERT, "" );


    if( madeCertRec.isCA() && madeCertRec.isSelf() )
        manApplet->mainWindow()->addRootCA( madeCertRec );

end :
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_PKI_resetCertInfo( &sMadeCertInfo );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binRenewCert );
    JS_BIN_reset( &binID );
    JS_BIN_reset( &binSignPri );
    JS_BIN_reset( &binSignCert );

    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightCertList( cert.getIssuerNum() );
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "fail to renew certificate" ), this );
        QDialog::reject();
    }
}

void RenewCertDlg::changeDayType( int index )
{
    QString strType = mDayTypeCombo->currentText();
    mDayLabel->setText( strType.toLower() + "s" );
}

void RenewCertDlg::clickUseDay()
{
    bool bVal = mUseDayCheck->isChecked();

    mDayText->setEnabled(bVal);
    mDayTypeCombo->setEnabled(bVal);
    mNotBeforeDateTime->setEnabled(!bVal);
    mNotAfterDateTime->setEnabled(!bVal);
}

void RenewCertDlg::clickKeepSerial()
{
    bool bVal = mKeepSerialCheck->isChecked();

    mSerialText->setEnabled( !bVal );
}

void RenewCertDlg::clickRevoke()
{
    bool bVal = mRevokeCheck->isChecked();

    mRevokeReasonLabel->setEnabled(bVal);
    mRevokeReasonCombo->setEnabled(bVal);
}
