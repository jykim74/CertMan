#include "make_crl_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "cert_rec.h"
#include "crl_policy_rec.h"
#include "key_pair_rec.h"
#include "db_mgr.h"
#include "crl_rec.h"


#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_util.h"
#include "commons.h"
#include "settings_mgr.h"


MakeCRLDlg::MakeCRLDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mIssuerNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(issuerChanged(int)));
    connect( mCRLDPCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(crldpChanged(int)));

    QStringList sRevokeLabels = { "Serial", "Reason", "Date" };
    mRevokeTable->setColumnCount(3);
    mRevokeTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeTable->setHorizontalHeaderLabels(sRevokeLabels);
    mRevokeTable->verticalHeader()->setVisible(false);

    initialize();
}

MakeCRLDlg::~MakeCRLDlg()
{

}

void MakeCRLDlg::setFixIssuer(QString strIssuerName)
{
    mIssuerNameCombo->setCurrentText( strIssuerName );
    mIssuerNameCombo->setDisabled(true);
    mAlgorithmText->setDisabled(true);
    mOptionText->setDisabled(true);
}

void MakeCRLDlg::accept()
{
    int         ret = 0;
    JIssueCRLInfo   sIssueCRLInfo;
    JCRLInfo   sMadeCRLInfo;
    JExtensionInfoList *pExtInfoList = NULL;
    JExtensionInfoList *pMadeExtInfoList = NULL;
    JRevokeInfoList *pRevokeInfoList = NULL;
    JRevokeInfoList *pMadeRevokeInfoList = NULL;

    BIN         binSignCert = {0,0};
    BIN         binSignPri = {0,0};
    BIN         binCRL = {0,0};

    char        *pHexCRL = NULL;

    CRLRec      madeCRLRec;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    int issuerIdx = mIssuerNameCombo->currentIndex();
    int policyIdx = mPolicyNameCombo->currentIndex();

    long uLastUpdate = -1;
    long uNextUpdate = -1;
    int nKeyType = -1;

    CertRec caCert = ca_cert_list_.at(issuerIdx);
    CRLPolicyRec policy = crl_policy_list_.at(policyIdx);
    KeyPairRec caKeyPair;

    memset( &sIssueCRLInfo, 0x00, sizeof(sIssueCRLInfo));
    memset( &sMadeCRLInfo, 0x00, sizeof(sMadeCRLInfo));

    dbMgr->getKeyPairRec( caCert.getKeyNum(), caKeyPair );

    if( caKeyPair.getAlg() == "RSA" )
        nKeyType = JS_PKI_KEY_TYPE_RSA;
    else if( caKeyPair.getAlg() == "EC" )
        nKeyType = JS_PKI_KEY_TYPE_ECC;

    JS_BIN_decodeHex( caCert.getCert().toStdString().c_str(), &binSignCert );
    JS_BIN_decodeHex( caKeyPair.getPrivateKey().toStdString().c_str(), &binSignPri );

    time_t now_t = time(NULL);

    if( policy.getLastUpdate() <= 0 )
    {
        long uValidSecs = policy.getNextUpdate() * 60 * 60 * 24;

        uLastUpdate = 0;
        uNextUpdate = uValidSecs;
    }
    else
    {
        uLastUpdate = policy.getLastUpdate() - now_t;
        uNextUpdate = policy.getNextUpdate() - now_t;
    }

    JS_PKI_setIssueCRLInfo( &sIssueCRLInfo,
                       policy.getVersion(),
                       policy.getHash().toStdString().c_str(),
                       uLastUpdate,
                       uNextUpdate );

    /* need to set revoked certificate information */

    QList<PolicyExtRec> policyExtList;
    dbMgr->getCRLPolicyExtensionList( policy.getNum(), policyExtList );
    for( int i=0; i < policyExtList.size(); i++ )
    {
        JExtensionInfo sExtInfo;
        PolicyExtRec policyExt = policyExtList.at(i);

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        if( policyExt.getSN() == kExtNameAKI )
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
        else if( policyExt.getSN() == kExtNameCRLNum )
        {
            QString strVal = policyExt.getValue();

            if( strVal.contains( "auto" ) )
            {
                int nSeq = dbMgr->getSeq( "TB_CRL" );
                QString strSeq;
                strSeq.sprintf( "%04x", nSeq );
                policyExt.setValue( strSeq );
            }
        }

        setExtInfoToDB( &sExtInfo, policyExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );
    }

    QList<RevokeRec> revokeList;
    QString strCRLDP = mCRLDPCombo->currentText();
    dbMgr->getRevokeList( caCert.getNum(), strCRLDP, revokeList );

    for( int i = 0; i < revokeList.size(); i++ )
    {
        JRevokeInfo sRevokeInfo;
        const char *pSerial = NULL;
        long uRevokeDate = -1;
        int nReason = -1;
        JExtensionInfo sExtReason;
        PolicyExtRec policyReason;

        RevokeRec revoke = revokeList.at(i);

        memset( &sRevokeInfo, 0x00, sizeof(sRevokeInfo) );
        memset( &sExtReason, 0x00, sizeof(sExtReason) );

        pSerial = revoke.getSerial().toStdString().c_str();
        nReason = revoke.getReason();
        uRevokeDate = revoke.getRevokeDate();

        policyReason.setSN( kExtNameCRLReason );
        policyReason.setCritical( true );
        policyReason.setValue( QString("%1").arg(nReason) );
        policyReason.setSeq(-1);

        setExtInfoToDB( &sExtReason, policyReason );

        JS_PKI_setRevokeInfo( &sRevokeInfo, pSerial, uRevokeDate, &sExtReason );

        if( pRevokeInfoList == NULL )
            JS_PKI_createRevokeInfoList( &sRevokeInfo, &pRevokeInfoList );
        else
            JS_PKI_appendRevokeInfoList( pRevokeInfoList, &sRevokeInfo );

        JS_PKI_resetRevokeInfo( &sRevokeInfo );
        JS_PKI_resetExtensionInfo( &sExtReason );
    }

    /* need to support extensions */

    if( caKeyPair.getAlg() == "PKCS11_RSA" || caKeyPair.getAlg() == "PKCS11_ECC" )
    {
        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotID();
        CK_SESSION_HANDLE hSession = getP11Session( pP11CTX, nSlotID );

        if( hSession < 0 )
        {
            goto end;
        }

        ret = JS_PKI_makeCRLByP11( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, &binSignCert, pP11CTX, hSession, &binCRL );

        JS_PKCS11_Logout( pP11CTX, hSession );
        JS_PKCS11_CloseSession( pP11CTX, hSession );
    }
    else
    {
        ret = JS_PKI_makeCRL( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, nKeyType, &binSignPri, &binSignCert, &binCRL );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to make CRL(%1)").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_getCRLInfo( &binCRL, &sMadeCRLInfo, &pMadeExtInfoList, &pMadeRevokeInfoList );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to get CRL information(%1)").arg(ret), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCRL, &pHexCRL );

    madeCRLRec.setRegTime( now_t );
    madeCRLRec.setIssuerNum( caCert.getNum() );
    madeCRLRec.setSignAlg( sMadeCRLInfo.pSignAlgorithm );
    madeCRLRec.setCRLDP( strCRLDP );
    madeCRLRec.setCRL( pHexCRL );

    dbMgr->addCRLRec( madeCRLRec );

end :
    JS_PKI_resetIssueCRLInfo( &sIssueCRLInfo );
    JS_PKI_resetCRLInfo( &sMadeCRLInfo );
    JS_BIN_reset( &binSignPri );
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binCRL );
    if( pHexCRL ) JS_free( pHexCRL );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
    if( pMadeExtInfoList ) JS_PKI_resetExtensionInfoList( &pMadeExtInfoList );
    if( pRevokeInfoList ) JS_PKI_resetRevokeInfoList( &pRevokeInfoList );
    if( pMadeRevokeInfoList ) JS_PKI_resetRevokeInfoList( &pMadeRevokeInfoList );

    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightCRLList( caCert.getNum() );
        QDialog::accept();
    }
}

void MakeCRLDlg::issuerChanged(int index)
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec issuerCert = ca_cert_list_.at(index);
    int nNum = issuerCert.getNum();

    KeyPairRec issuerKeyPair;
    dbMgr->getKeyPairRec( issuerCert.getKeyNum(), issuerKeyPair );

    mAlgorithmText->setText( issuerKeyPair.getAlg() );
    mOptionText->setText( issuerKeyPair.getParam() );

    QList<QString> crldpList;
    dbMgr->getCRLDPListFromCert( nNum, crldpList );

    mCRLDPCombo->clear();

    for( int i = 0; i < crldpList.size(); i++ )
        mCRLDPCombo->addItem( crldpList.at(i) );

    setRevokeList();
}

void MakeCRLDlg::crldpChanged(int index )
{
    setRevokeList();
}

void MakeCRLDlg::initialize()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    ca_cert_list_.clear();
    mIssuerNameCombo->clear();

    dbMgr->getCACertList( ca_cert_list_ );
    for( int i=0; i < ca_cert_list_.size(); i++ )
    {
        CertRec certRec = ca_cert_list_.at(i);
        mIssuerNameCombo->addItem( certRec.getSubjectDN() );
    }

    crl_policy_list_.clear();

    dbMgr->getCRLPolicyList( crl_policy_list_ );
    for( int i = 0; i < crl_policy_list_.size(); i++ )
    {
        CRLPolicyRec policyRec = crl_policy_list_.at(i);
        mPolicyNameCombo->addItem( policyRec.getName() );
    }

    setRevokeList();
}

void MakeCRLDlg::setRevokeList()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    int rowCnt = mRevokeTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mRevokeTable->removeRow(0);

    QList<RevokeRec> revokeList;
    CertRec issuer = ca_cert_list_.at( mIssuerNameCombo->currentIndex() );
    QString strCRLDP= mCRLDPCombo->currentText();

    dbMgr->getRevokeList( issuer.getNum(), strCRLDP, revokeList );

    for( int i=0; i < revokeList.size(); i++ )
    {
        RevokeRec revoke = revokeList.at(i);
        char sDateTime[64];

        JS_UTIL_getDateTime( revoke.getRevokeDate(), sDateTime );
        QString strDate = sDateTime;
        QString strReason = JS_PKI_getRevokeReasonName( revoke.getReason() );

        mRevokeTable->insertRow(i);
        mRevokeTable->setItem( i, 0, new QTableWidgetItem( revoke.getSerial() ));
        mRevokeTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( strReason ) ));
        mRevokeTable->setItem( i, 2, new QTableWidgetItem( sDateTime ));
    }
}
