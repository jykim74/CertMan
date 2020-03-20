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
#include "commons.h"
#include "settings_mgr.h"

static QStringList	sRevokeReasonList = {
    "unused", "keyCompromise", "CACompromise",
    "affiliationChanged", "superseded", "cessationOfOperation",
    "certificateHold", "privilegeWithdrawn", "AACompromise"
};

MakeCRLDlg::MakeCRLDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mIssuerNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(issuerChanged(int)));
    connect( mRevokeAddBtn, SIGNAL(clicked()), this, SLOT(clickRevokeAdd()));

    mRevokeReasonCombo->addItems(sRevokeReasonList);

    QStringList sRevokeLabels = { "Serial", "Reason", "Date" };
    mRevokeTable->setColumnCount(3);
    mRevokeTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeTable->setHorizontalHeaderLabels(sRevokeLabels);

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

    if( policy.getLastUpdate() <= 0 )
    {
        long uValidSecs = policy.getNextUpdate() * 60 * 60 * 24;

        uLastUpdate = 0;
        uNextUpdate = uValidSecs;
    }
    else
    {
        time_t now_t = time(NULL);
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

    int nRevokeCnt = mRevokeTable->rowCount();
    for( int i = 0; i < nRevokeCnt; i++ )
    {
        JRevokeInfo sRevokeInfo;
        const char *pSerial = NULL;
        long uRevokeDate = -1;
        int nReason = -1;
        JExtensionInfo sExtReason;
        PolicyExtRec policyReason;

        memset( &sRevokeInfo, 0x00, sizeof(sRevokeInfo) );
        memset( &sExtReason, 0x00, sizeof(sExtReason) );

        pSerial = mRevokeTable->takeItem(i, 0)->text().toStdString().c_str();
        nReason = mRevokeTable->takeItem(i, 1)->text().toInt();
        uRevokeDate = mRevokeTable->takeItem(i,2)->data(0).toInt();

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

    madeCRLRec.setIssuerNum( caCert.getNum() );
    madeCRLRec.setSignAlg( sMadeCRLInfo.pSignAlgorithm );
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

    QList<CertRec> certList;
    dbMgr->getCertList( nNum, certList );

    mCertCombo->clear();

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec cert = certList.at(i);
        QVariant objVal = QVariant( cert.getNum() );
        mCertCombo->addItem( cert.getSubjectDN(), objVal );
    }

    setRevokeList();
}

void MakeCRLDlg::clickRevokeAdd()
{
   QVariant objVal = mCertCombo->currentData();
   QString strSerail = objVal.toString();
   QString strReason = mRevokeReasonCombo->currentText();
   QString strDate = mRevokeDateTime->dateTime().toString();
   QVariant objDate = QVariant( mRevokeDateTime->dateTime().toTime_t() );

   int row = mRevokeTable->rowCount();
   mRevokeTable->setRowCount( row + 1 );

   QTableWidgetItem *dateItem = new QTableWidgetItem( strDate );
   dateItem->setData( 0, objDate );

   mRevokeTable->setItem( row, 0, new QTableWidgetItem( strSerail ));
   mRevokeTable->setItem( row, 1, new QTableWidgetItem( strReason ));
//   mRevokeTable->setItem( row, 2, new QTableWidgetItem( strDate ) );
   mRevokeTable->setItem( row, 2, dateItem );
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

    QDateTime dateTime = QDateTime::currentDateTime();
    mRevokeDateTime->setDateTime( dateTime );

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
    dbMgr->getRevokeList( issuer.getNum(), revokeList );

    for( int i=0; i < revokeList.size(); i++ )
    {
        RevokeRec revoke = revokeList.at(i);
        QVariant objDate = revoke.getRevokeDate();

        QDateTime dateTime;
        dateTime.fromTime_t( revoke.getRevokeDate() );
        QString strDate = dateTime.toString();

        QTableWidgetItem *dateItem = new QTableWidgetItem( strDate );
        dateItem->setData(0, objDate);

        mRevokeTable->insertRow(i);
        mRevokeTable->setItem( i, 0, new QTableWidgetItem( revoke.getSerial() ));
        mRevokeTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg(revoke.getReason()) ));
 //       mRevokeTable->setItem( i, 2, new QTableWidgetItem( revoke.getRevokeDate() ));
        mRevokeTable->setItem( i, 2, dateItem );
    }
}
