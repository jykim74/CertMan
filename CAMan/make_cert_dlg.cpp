#include "make_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "req_rec.h"
#include "cert_rec.h"
#include "user_rec.h"
#include "cert_policy_rec.h"
#include "key_pair_rec.h"
#include "db_mgr.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "commons.h"
#include "settings_mgr.h"

static int g_iVerbose = 1;

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
    connect( mPolicyNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(policyChanged(int)));
    connect( mSelfSignCheck, SIGNAL(clicked()), this, SLOT(clickSelfSign()));

    initialize();
}

MakeCertDlg::~MakeCertDlg()
{

}


void MakeCertDlg::initialize()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    req_list_.clear();

    dbMgr->getReqList( 0, req_list_ );
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

    cert_policy_list_.clear();

    dbMgr->getCertPolicyList( cert_policy_list_ );
    for( int i=0; i < cert_policy_list_.size(); i++ )
    {
        CertPolicyRec certPolicyRec = cert_policy_list_.at(i);
        mPolicyNameCombo->addItem( certPolicyRec.getName() );
    }

    setSubjectDN();
}

void MakeCertDlg::setSubjectDN()
{
    CertPolicyRec   policy = cert_policy_list_.at(mPolicyNameCombo->currentIndex());

    if( policy.getDNTemplate() == "#CSR" )
    {
        ReqRec req = req_list_.at( mReqNameCombo->currentIndex() );

        mSubjectDNText->setText( req.getDN() );
    }
    else
    {
        mSubjectDNText->setText( policy.getDNTemplate() );
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
    mIssuerNameCombo->setDisabled(true);
    mIssuerAlgorithmText->setDisabled(true);
    mIssuerOptionText->setDisabled(true);
    mSelfSignCheck->setDisabled(true);
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
    BIN binPubVal = {0,0};

    char sKeyID[128];
    char *pHexCRLDP = NULL;
    char *pCRLDP = NULL;

    memset( sKeyID, 0x00, sizeof(sKeyID));

    CertRec madeCertRec;
    JExtensionInfoList *pExtInfoList = NULL;
    JExtensionInfoList *pMadeExtInfoList = NULL;

    QTextCodec *codec = QTextCodec::codecForName("UTF-16");
    QByteArray ba;

    UserRec userRec;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;
    bool bSelf = mSelfSignCheck->isChecked();

    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sMadeCertInfo, 0x00, sizeof(sMadeCertInfo));
    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    if( req_list_.size() <= 0 )
    {
        manApplet->warningBox( tr("There is no request"), this );
        return;
    }

    if( cert_policy_list_.size() <= 0 )
    {
        manApplet->warningBox( tr( "There is no certificate policy"), this );
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

    int reqIdx =  mReqNameCombo->currentIndex();
    int policyIdx = mPolicyNameCombo->currentIndex();
    int issuerIdx = mIssuerNameCombo->currentIndex();

    int nSignKeyNum = -1;
    int nKeyType = -1;
    int nIssuerNum = -1;

    CertPolicyRec policyRec = cert_policy_list_.at( policyIdx );
    ReqRec reqRec = req_list_.at( reqIdx );

    JS_BIN_decodeHex( reqRec.getCSR().toStdString().c_str(), &binCSR );
    JS_PKI_getReqInfo( &binCSR, &sReqInfo, NULL );

    if( sReqInfo.bVerify == 0 )
    {
        manApplet->warningBox(tr("Request is not verified"), this );
        return;
    }

    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
    JS_PKI_getPublicKeyValue( &binPub, &binPubVal );
    JS_PKI_getKeyIdentifier( &binPubVal, sKeyID );

    if( bSelf )
        nSignKeyNum = reqRec.getKeyNum();
    else {
        CertRec issuerCert = ca_cert_list_.at( issuerIdx );
        nSignKeyNum = issuerCert.getKeyNum();
        nIssuerNum = issuerCert.getNum();
        JS_BIN_decodeHex( issuerCert.getCert().toStdString().c_str(), &binSignCert );
    }

    KeyPairRec signKeyPair;
    dbMgr->getKeyPairRec( nSignKeyNum, signKeyPair );

    /* need to work more */

    QString strSerial;
    int nSeq = dbMgr->getSeq( "TB_CERT" );

    strSerial = QString("%1").arg(nSeq);
    QString strSignAlg = getSignAlg( signKeyPair.getAlg(), policyRec.getHash() );
    if( signKeyPair.getAlg() == "RSA" || signKeyPair.getAlg() == "PKCS11_RSA" )
        nKeyType = JS_PKI_KEY_TYPE_RSA;
    else if( signKeyPair.getAlg() == "EC" || signKeyPair.getAlg() == "PKCS11_ECC" )
        nKeyType = JS_PKI_KEY_TYPE_ECC;


//    QString strDN = mSubjectDNText->text();
    QString strDN = getRealSubjectDN();

    time_t now_t = time(NULL);
    long notBefore = -1;
    long notAfter = -1;

    if( policyRec.getNotBefore() <= 0 )
    {
        long uValidSecs = policyRec.getNotAfter() * 60 * 60 * 24;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else
    {
        notBefore = policyRec.getNotBefore() - now_t;
        notAfter = policyRec.getNotAfter() - now_t;
    }


    JS_BIN_decodeHex( signKeyPair.getPrivateKey().toStdString().c_str(), &binSignPri );

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                        policyRec.getVersion(),
                        strSerial.toStdString().c_str(),
                        policyRec.getHash().toStdString().c_str(),
                        strDN.toStdString().c_str(),
                        notBefore,
                        notAfter,
                        sReqInfo.nKeyAlg,
                        sReqInfo.pPublicKey );

    /* need to support extensions start */
    QList<PolicyExtRec> policyExtList;
    dbMgr->getCertPolicyExtensionList( policyRec.getNum(), policyExtList );
    for( int i=0; i < policyExtList.size(); i++ )
    {
        JExtensionInfo sExtInfo;
        PolicyExtRec policyExt = policyExtList.at(i);

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        if( policyExt.getSN() == kExtNameBC )
        {
            QString strVal = policyExt.getValue();
            if( strVal.contains( "CA#" ) == true )
                bCA = true;
            else
                bCA = false;
        }
        else if( policyExt.getSN() == kExtNameSKI )
        {
            policyExt.setValue( sKeyID );
        }
        else if( policyExt.getSN() == kExtNameCRLDP )
        {
            char *pDN = NULL;
            JS_PKI_getDP( policyExt.getValue().toStdString().c_str(), nSeq, &pDN );
            policyExt.setValue( pDN );
            if( pDN ) JS_free( pDN );
        }
        else if( policyExt.getSN() == kExtNameSAN )
        {
            QString strAltName = policyExt.getValue();
            QString strReplace = getReplacedValue( strAltName );
            policyExt.setValue( strAltName );
        }
        else if( policyExt.getSN() == kExtNameAKI )
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
                QString strVal = QString( "KEYID$%1#ISSUER$%2#SERIAL$%3").arg( sHexID ).arg( sHexIssuer ).arg( sHexSerial );
                policyExt.setValue( strVal );

                JS_BIN_reset( &binCert );
            }
            else
            {
                /* SelfSign 경우 무시 한다. */
                continue;
            }
        }

        transExtInfoFromDBRec( &sExtInfo, policyExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );
    }
    /* need to support extensions end */

    if( signKeyPair.getAlg() == "PKCS11_RSA" || signKeyPair.getAlg() == "PKCS11_ECC" )
    {
        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotID();
        BIN binID = {0,0};

        CK_SESSION_HANDLE hSession = getP11Session( pP11CTX, nSlotID );
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
    else
    {
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
    madeCertRec.setStatus(0);
    madeCertRec.setSignAlg( sMadeCertInfo.pSignAlgorithm );
    madeCertRec.setCert( pHexCert );

    ba = sMadeCertInfo.pSubjectName;
    madeCertRec.setSubjectDN( codec->toUnicode( ba ) );

    madeCertRec.setRegTime( now_t );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );
    madeCertRec.setKeyNum( reqRec.getKeyNum() );
    madeCertRec.setCA( bCA );
    madeCertRec.setIssuerNum( nIssuerNum );
    madeCertRec.setSerial( sMadeCertInfo.pSerial );
    madeCertRec.setDNHash( sMadeCertInfo.pDNHash );
    if( pCRLDP ) madeCertRec.setCRLDP( pCRLDP );
    JS_BIN_decodeHex( sMadeCertInfo.pPublicKey, &binPub );
    madeCertRec.setKeyHash( sKeyID );

    dbMgr->addCertRec( madeCertRec );
    dbMgr->modReqStatus( reqRec.getSeq(), 1 );


    userRec.setName( mUserNameText->text() );
    userRec.setSSN( mSSNText->text() );
    userRec.setEmail( mEmailText->text() );
    userRec.setRegTime( time(NULL));
    if( userRec.getName().length() > 0 ) dbMgr->addUserRec( userRec );

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
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pMadeExtInfoList ) JS_PKI_resetExtensionInfoList( &pMadeExtInfoList );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPubVal );
    JS_PKI_resetReqInfo( &sReqInfo );
    if( pHexCRLDP ) JS_free( pHexCRLDP );
    if( pCRLDP ) JS_free( pCRLDP );

    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightCertList( nIssuerNum );
        QDialog::accept();
    }
}

void MakeCertDlg::reqChanged( int index )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    ReqRec reqRec = req_list_.at(index);

    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( reqRec.getKeyNum(), keyPair );

    mAlgorithmText->setText( keyPair.getAlg() );
    mOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::issuerChanged( int index )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec certRec = ca_cert_list_.at(index);
    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mIssuerAlgorithmText->setText( keyPair.getAlg() );
    mIssuerOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::policyChanged(int index )
{
    setSubjectDN();
}

void MakeCertDlg::clickSelfSign()
{
    bool bStatus = mSelfSignCheck->isChecked();

    mIssuerNameCombo->setEnabled( !bStatus );
    mIssuerAlgorithmText->setEnabled( !bStatus );
    mIssuerOptionText->setEnabled( !bStatus );
}
