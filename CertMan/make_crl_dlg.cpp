/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "make_crl_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "cert_rec.h"
#include "crl_profile_rec.h"
#include "key_pair_rec.h"
#include "db_mgr.h"
#include "crl_rec.h"

#include "js_gen.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "js_define.h"
#include "commons.h"
#include "settings_mgr.h"


MakeCRLDlg::MakeCRLDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mIssuerNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(issuerChanged(int)));
    connect( mCRLDPCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(crldpChanged(int)));

    QStringList sRevokeLabels = { tr("Serial"), tr("Reason"), tr("Date") };
    mRevokeTable->setColumnCount(3);
    mRevokeTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeTable->setHorizontalHeaderLabels(sRevokeLabels);
    mRevokeTable->verticalHeader()->setVisible(false);

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

MakeCRLDlg::~MakeCRLDlg()
{

}

void MakeCRLDlg::showEvent(QShowEvent *event)
{
    if( ca_cert_list_.size() <= 0 )
    {
        manApplet->warningBox( tr("There is no CA certficate"), this );
        destroy();
        return;
    }

    if( crl_profile_list_.size() <= 0 )
    {
        manApplet->warningBox(tr("There is no CRL Profile"), this );
        destroy(true);
        return;
    }
//    initialize();
}

void MakeCRLDlg::setFixIssuer(QString strIssuerName )
{
    qDebug() << "IssuerName: " << strIssuerName;

    mIssuerNameCombo->setCurrentText( strIssuerName );
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

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int issuerIdx = mIssuerNameCombo->currentIndex();
    int profileIdx = mProfileNameCombo->currentIndex();

    long uThisUpdate = -1;
    long uNextUpdate = -1;
//    int nKeyType = -1;

    CertRec caCert = ca_cert_list_.at(issuerIdx);
    CRLProfileRec profile = crl_profile_list_.at(profileIdx);
    KeyPairRec caKeyPair;

    if( caCert.getStatus() == JS_CERT_STATUS_REVOKE )
    {
        QString strMsg = tr( "The CA certificate has been revoked. continue?" );
        bool bVal = manApplet->yesOrNoBox( strMsg, NULL );
        if( bVal == false ) return;
    }

    memset( &sIssueCRLInfo, 0x00, sizeof(sIssueCRLInfo));
    memset( &sMadeCRLInfo, 0x00, sizeof(sMadeCRLInfo));

    dbMgr->getKeyPairRec( caCert.getKeyNum(), caKeyPair );

    time_t now_t = -1;
    QList<ProfileExtRec> profileExtList;
    QList<RevokeRec> revokeList;
    QString strCRLDP = mCRLDPCombo->currentText();
    int nSeq = dbMgr->getNextVal( "TB_CRL" );

    if( caKeyPair.getParam() == "SM2" )
    {
        if( profile.getHash() != "SM3" )
        {
            QString strMsg = tr( "The hash(%1) in the profile is not SM3. Would you like to change to SM3?" ).arg( profile.getHash() );
            bool bVal = manApplet->yesOrNoBox( strMsg, this, true );

            if( bVal )
            {
                profile.setHash( "SM3" );
            }
            else
            {
                goto end;
            }
        }
    }
    else if( caKeyPair.getAlg() != kMechEdDSA )
    {
        if( profile.getHash() == "SM3" )
        {
            QString strMsg = tr( "SM3 hash cannot be used in profiles (%1:%2)" )
                    .arg( caKeyPair.getAlg() )
                    .arg( caKeyPair.getParam() );

            manApplet->warningBox( strMsg, this );
            goto end;
        }
    }

    JS_BIN_decodeHex( caCert.getCert().toStdString().c_str(), &binSignCert );


    now_t = time(NULL);

    if( profile.getThisUpdate() == 0 )
    {
        long uValidSecs = profile.getNextUpdate() * 60 * 60 * 24;

        uThisUpdate = 0;
        uNextUpdate = uValidSecs;
    }
    else if( profile.getThisUpdate() == 1 )
    {
        long uValidSecs = profile.getNextUpdate() * 60 * 60 * 24 * 30;

        uThisUpdate = 0;
        uNextUpdate = uValidSecs;
    }
    else if( profile.getThisUpdate() == 2 )
    {
        long uValidSecs = profile.getNextUpdate() * 60 * 60 * 24 * 365;

        uThisUpdate = 0;
        uNextUpdate = uValidSecs;
    }
    else
    {
        uThisUpdate = profile.getThisUpdate() - now_t;
        uNextUpdate = profile.getNextUpdate() - now_t;
    }

    JS_PKI_setIssueCRLInfo( &sIssueCRLInfo,
                       profile.getVersion(),
                       profile.getHash().toStdString().c_str(),
                       uThisUpdate,
                       uNextUpdate );

    /* need to set revoked certificate information */



    dbMgr->getCRLProfileExtensionList( profile.getNum(), profileExtList );
    for( int i=0; i < profileExtList.size(); i++ )
    {
        JExtensionInfo sExtInfo;
        ProfileExtRec profileExt = profileExtList.at(i);

        memset( &sExtInfo, 0x00, sizeof(sExtInfo));

        if( profileExt.getSN() == JS_PKI_ExtNameAKI )
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
        else if( profileExt.getSN() == JS_PKI_ExtNameCRLNum )
        {
            QString strVal = profileExt.getValue();

            if( strVal.contains( "auto" ) )
            {
                QString strSeq;
                strSeq = QString( "%1" ).arg( nSeq, 4, 16, QLatin1Char('0'));
                profileExt.setValue( strSeq );
            }
        }

        transExtInfoFromDBRec( &sExtInfo, profileExt );
        JS_PKI_addExtensionInfoList( &pExtInfoList, &sExtInfo );
    }


    dbMgr->getRevokeList( caCert.getNum(), strCRLDP, revokeList );

    for( int i = 0; i < revokeList.size(); i++ )
    {
        JRevokeInfo sRevokeInfo;
        const char *pSerial = NULL;
        long uRevokeDate = -1;
        int nReason = -1;
        JExtensionInfo sExtReason;
        ProfileExtRec profileReason;

        RevokeRec revoke = revokeList.at(i);

        memset( &sRevokeInfo, 0x00, sizeof(sRevokeInfo) );
        memset( &sExtReason, 0x00, sizeof(sExtReason) );

        pSerial = revoke.getSerial().toStdString().c_str();
        nReason = revoke.getReason();
        uRevokeDate = revoke.getRevokeDate();

        profileReason.setSN( JS_PKI_ExtNameCRLReason );
        profileReason.setCritical( true );
        profileReason.setValue( QString("%1").arg(nReason) );
        profileReason.setSeq(-1);

        transExtInfoFromDBRec( &sExtReason, profileReason );

        JS_PKI_setRevokeInfo( &sRevokeInfo, pSerial, uRevokeDate, &sExtReason );

        if( pRevokeInfoList == NULL )
            JS_PKI_createRevokeInfoList( &sRevokeInfo, &pRevokeInfoList );
        else
            JS_PKI_appendRevokeInfoList( pRevokeInfoList, &sRevokeInfo );

        JS_PKI_resetRevokeInfo( &sRevokeInfo );
        JS_PKI_resetExtensionInfo( &sExtReason );
    }

    /* need to support extensions */

    if( caKeyPair.getAlg() == kMechPKCS11_RSA || caKeyPair.getAlg() == kMechPKCS11_EC || caKeyPair.getAlg() == kMechPKCS11_DSA )
    {
        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        BIN binID = {0,0};
        int nSlotID = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        CK_SESSION_HANDLE hSession = getP11Session( pP11CTX, nSlotID, strPIN );

        if( hSession < 0 )
        {
            goto end;
        }

        JS_BIN_decodeHex( caKeyPair.getPrivateKey().toStdString().c_str(), &binID );

        ret = JS_PKI_makeCRLByP11( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, &binID, &binSignCert, pP11CTX, &binCRL );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
        JS_BIN_reset( &binID );
    }
    else if( caKeyPair.getAlg() == kMechKMIP_RSA || caKeyPair.getAlg() == kMechKMIP_EC )
    {
        if( manApplet->settingsMgr()->KMIPUse() == 0 )
            goto end;

        SSL_CTX *pCTX = NULL;
        SSL *pSSL = NULL;
        Authentication  *pAuth = NULL;
        BIN binID = {0,0};

        JS_BIN_decodeHex( caKeyPair.getPrivateKey().toStdString().c_str(), &binID );

        ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );

        if( ret == 0 )
        {
            ret = JS_PKI_makeCRLByKMIP( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, &binID, &binSignCert, pSSL, pAuth, &binCRL );
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
            manApplet->getDecPriBIN( caKeyPair.getPrivateKey(), &binSignPri );
        else
            JS_BIN_decodeHex( caKeyPair.getPrivateKey().toStdString().c_str(), &binSignPri );

        ret = JS_PKI_makeCRL( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, &binSignPri, &binSignCert, &binCRL );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to make CRL [%1]").arg(ret), this );
        goto end;
    }

    ret = JS_PKI_getCRLInfo( &binCRL, &sMadeCRLInfo, &pMadeExtInfoList, &pMadeRevokeInfoList );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get CRL information [%1]").arg(ret), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCRL, &pHexCRL );

    madeCRLRec.setNum( nSeq );
    madeCRLRec.setRegTime( now_t );
    madeCRLRec.setIssuerNum( caCert.getNum() );
    madeCRLRec.setSignAlg( sMadeCRLInfo.pSignAlgorithm );
    madeCRLRec.setCRLDP( strCRLDP );
    madeCRLRec.setCRL( pHexCRL );

    ret = dbMgr->addCRLRec( madeCRLRec );
    if( ret != 0 ) goto end;

    if( manApplet->isPRO() ) addAudit( dbMgr, JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_CRL, strCRLDP );

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
        manApplet->settingsMgr()->setCRLProfileNum( mProfileNameCombo->currentIndex() );
        manApplet->settingsMgr()->setIssuerNum( mIssuerNameCombo->currentIndex() );

        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "failed to make CRL [%1]" ).arg(ret), this );
        QDialog::reject();
    }
}

void MakeCRLDlg::issuerChanged(int index)
{
    DBMgr* dbMgr = manApplet->dbMgr();
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
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    mCRLDPCombo->setEditable(true);
    ca_cert_list_.clear();
    mIssuerNameCombo->clear();

    dbMgr->getIssuerCertList( ca_cert_list_ );


    for( int i=0; i < ca_cert_list_.size(); i++ )
    {
        CertRec certRec = ca_cert_list_.at(i);
        mIssuerNameCombo->addItem( certRec.getSubjectDN() );
    }

    if( manApplet->settingsMgr()->issuerNum() < ca_cert_list_.size() )
        mIssuerNameCombo->setCurrentIndex( manApplet->settingsMgr()->issuerNum() );

    crl_profile_list_.clear();

    dbMgr->getCRLProfileList( crl_profile_list_ );

    if( crl_profile_list_.size() <= 0 )
    {
        manApplet->warningBox( tr( "There is no CRL profile"), this );
        return;
    }

    for( int i = 0; i < crl_profile_list_.size(); i++ )
    {
        CRLProfileRec profileRec = crl_profile_list_.at(i);
        mProfileNameCombo->addItem( profileRec.getName() );
    }

    if( manApplet->settingsMgr()->CRLProfileNum() < crl_profile_list_.size() )
        mProfileNameCombo->setCurrentIndex( manApplet->settingsMgr()->CRLProfileNum() );

    setRevokeList();
}

void MakeCRLDlg::setRevokeList()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    mRevokeTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

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
        mRevokeTable->setRowHeight( i, 10 );
        mRevokeTable->setItem( i, 0, new QTableWidgetItem( revoke.getSerial() ));
        mRevokeTable->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( strReason ) ));
        mRevokeTable->setItem( i, 2, new QTableWidgetItem( sDateTime ));
    }
}
