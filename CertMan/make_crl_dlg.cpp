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
#include "profile_man_dlg.h"
#include "ca_man_dlg.h"
#include "view_crl_profile_dlg.h"


MakeCRLDlg::MakeCRLDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mIssuerNumText, SIGNAL(textChanged(QString)), this, SLOT(issuerNumChanged()));
    connect( mCRLDPCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(crldpChanged(int)));
    connect( mSelectProfileBtn, SIGNAL(clicked()), this, SLOT(clickSelectProfile()));
    connect( mViewProfileBtn, SIGNAL(clicked()), this, SLOT(clickViewProfile()));
    connect( mSelectIssuerBtn, SIGNAL(clicked()), this, SLOT(clickSelectIssuer()));
    connect( mProfileNumText, SIGNAL(textChanged(QString)), this, SLOT(profileNumChanged()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeCRLDlg::~MakeCRLDlg()
{

}

void MakeCRLDlg::showEvent(QShowEvent *event)
{

}

void MakeCRLDlg::setIssuerNum( int nIssuerNum )
{
    mIssuerNumText->setText( QString("%1").arg( nIssuerNum) );
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

    if( mIssuerNumText->text().length() < 1 )
    {
        clickSelectIssuer();
        if( mIssuerNumText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Please select CA certificate"), this );
            return;
        }
    }

    int issuerIdx = mIssuerNumText->text().toInt();

    if( mProfileNumText->text().length() < 1 )
    {
        clickSelectProfile();
        if( mProfileNameText->text().length() < 1 )
        {
            manApplet->warningBox( tr( "Please select a profile"), this );
            return;
        }
    }

    QString strProfileNum = mProfileNumText->text();


    int profileIdx = strProfileNum.toInt();

    time_t tThisUpdate = -1;
    time_t tNextUpdate = -1;
//    int nKeyType = -1;

    CertRec caCert;
    CRLProfileRec profile;
    KeyPairRec caKeyPair;

    manApplet->dbMgr()->getCertRec( issuerIdx, caCert );
    manApplet->dbMgr()->getCRLProfileRec( profileIdx, profile );

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
        }
    }
    else if( caKeyPair.getAlg() != JS_PKI_KEY_TYPE_ECDSA )
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

    JS_PKI_getPeriod(
        profile.getThisUpdate(),
        profile.getNextUpdate(),
        now_t,
        &tThisUpdate,
        &tNextUpdate );

    JS_PKI_setIssueCRLInfo( &sIssueCRLInfo,
                       profile.getVersion(),
                       profile.getHash().toStdString().c_str(),
                       tThisUpdate,
                       tNextUpdate );

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

            JS_BIN_decodeHex( caCert.getCert().toStdString().c_str(), &binCert );

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

        ret = transExtInfoFromDBRec( &sExtInfo, profileExt );
        if( ret == 0 )
            JS_PKI_addExtensionInfoList( &pExtInfoList, &sExtInfo );
    }


    dbMgr->getRevokeList( caCert.getNum(), strCRLDP, revokeList );

    for( int i = 0; i < revokeList.size(); i++ )
    {
        JRevokeInfo sRevokeInfo;
        const char *pSerial = NULL;
        time_t tRevokeDate = -1;
        int nReason = -1;
        JExtensionInfo sExtReason;
        ProfileExtRec profileReason;

        RevokeRec revoke = revokeList.at(i);

        memset( &sRevokeInfo, 0x00, sizeof(sRevokeInfo) );
        memset( &sExtReason, 0x00, sizeof(sExtReason) );

        pSerial = revoke.getSerial().toStdString().c_str();
        nReason = revoke.getReason();
        tRevokeDate = revoke.getRevokeDate();

        profileReason.setSN( JS_PKI_ExtNameCRLReason );
        profileReason.setCritical( true );
        profileReason.setValue( QString("%1").arg(nReason) );
        profileReason.setSeq(-1);

        transExtInfoFromDBRec( &sExtReason, profileReason );

        JS_PKI_setRevokeInfo( &sRevokeInfo, pSerial, tRevokeDate, &sExtReason );

        if( pRevokeInfoList == NULL )
            JS_PKI_createRevokeInfoList( &sRevokeInfo, &pRevokeInfoList );
        else
            JS_PKI_appendRevokeInfoList( pRevokeInfoList, &sRevokeInfo );

        JS_PKI_resetRevokeInfo( &sRevokeInfo );
        JS_PKI_resetExtensionInfo( &sExtReason );
    }

    /* need to support extensions */
    if( isPKCS11Private( caKeyPair.getAlg() ) == true )
    {
        if( manApplet->settingsMgr()->PKCS11Use() == false )
        {
            manApplet->warningBox( tr("No PKCS11 settings"), this );
            ret = -1;
            goto end;
        }

        JP11_CTX    *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        BIN binID = {0,0};
        int nSlotID = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        if( pP11CTX == NULL )
        {
            manApplet->warningBox( tr("PKCS11 library was not loaded"), this );
            ret = -1;
            goto end;
        }

        ret = getP11Session( pP11CTX, nSlotID, strPIN );

        if( ret != 0 )
        {
            manApplet->warningBox( tr( "Failed to fetch session:%1 ").arg( ret ), this);
            ret = -1;
            goto end;
        }

        JS_BIN_decodeHex( caKeyPair.getPrivateKey().toStdString().c_str(), &binID );

        ret = JS_PKI_makeCRLByP11( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, &binID, &binSignCert, pP11CTX, &binCRL );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
        JS_BIN_reset( &binID );
    }
    else if(  isKMIPPrivate( caKeyPair.getAlg() ) == true )
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

        manApplet->getPriKey( caKeyPair.getPrivateKey(), &binSignPri );

        ret = JS_PKI_makeCRL( &sIssueCRLInfo, pExtInfoList, pRevokeInfoList, &binSignPri, &binSignCert, &binCRL );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to make CRL [%1]").arg(JERR(ret)), this );
        goto end;
    }

    ret = JS_PKI_getCRLInfo( &binCRL, &sMadeCRLInfo, &pMadeExtInfoList, &pMadeRevokeInfoList );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("failed to get CRL information [%1]").arg(JERR(ret)), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCRL, &pHexCRL );

    madeCRLRec.setNum( nSeq );
    madeCRLRec.setRegTime( now_t );
    madeCRLRec.setIssuerNum( caCert.getNum() );
    madeCRLRec.setThisUpdate( tThisUpdate );
    madeCRLRec.setNextUpdate( tNextUpdate );
    madeCRLRec.setSignAlg( sMadeCRLInfo.pSignAlgorithm );
    madeCRLRec.setCRLDP( strCRLDP );
    madeCRLRec.setCRL( pHexCRL );

    ret = dbMgr->addCRLRec( madeCRLRec );
    if( ret != 0 )
    {
        manApplet->warnLog( tr("Failed to save DB : %1").arg( JERR(ret) ), this );
        goto end;
    }

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
        manApplet->settingsMgr()->setCRLProfileNum( mProfileNumText->text().toInt() );
        manApplet->settingsMgr()->setIssuerNum( mIssuerNumText->text().toInt() );

        QDialog::accept();
    }
}

void MakeCRLDlg::issuerNumChanged()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int nNum = mIssuerNumText->text().toInt();
    CertRec issuerCert;

    int ret = dbMgr->getCertRec( nNum, issuerCert );
    if(ret != 0 )
    {
        mIssuerNumText->clear();
        return;
    }

    mIssuerNameText->setText( issuerCert.getSubjectDN() );

    KeyPairRec issuerKeyPair;
    dbMgr->getKeyPairRec( issuerCert.getKeyNum(), issuerKeyPair );

    mOptionLabel->setText( getParamLabel(issuerKeyPair.getAlg()) );
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

void MakeCRLDlg::profileNumChanged()
{
    int nNum = mProfileNumText->text().toInt();
    CRLProfileRec profileRec;

    int ret = manApplet->dbMgr()->getCRLProfileRec( nNum, profileRec );
    if( ret != 0 )
    {
        mProfileNumText->clear();
        return;
    }

    mProfileNameText->setText( profileRec.getName() );
}

void MakeCRLDlg::initUI()
{
    QStringList sRevokeLabels = { tr("Serial"), tr("Reason"), tr("Date") };
    mRevokeTable->setColumnCount( sRevokeLabels.size() );
    mRevokeTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeTable->setHorizontalHeaderLabels(sRevokeLabels);
    mRevokeTable->verticalHeader()->setVisible(false);
    mRevokeTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mRevokeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mIssuerNameText->setPlaceholderText( tr( "Select a CA certificate from CA Man" ) );
}

void MakeCRLDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    mCRLDPCombo->setEditable(true);

    if( manApplet->settingsMgr()->issuerNum() > 0 )
        mIssuerNumText->setText( QString("%1").arg( manApplet->settingsMgr()->issuerNum() ));

    if( manApplet->settingsMgr()->CRLProfileNum() > 0 )
        mProfileNumText->setText( QString("%1").arg( manApplet->settingsMgr()->CRLProfileNum() ));

    setRevokeList();

    mProfileNameText->setPlaceholderText( tr( "Select a profile from Profile Man" ));
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
    int nNum = mIssuerNumText->text().toInt();
    CertRec issuer;
    dbMgr->getCertRec( nNum, issuer );
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

void MakeCRLDlg::clickSelectIssuer()
{
    CAManDlg caMan;
    caMan.setTitle( tr( "Select CA certificate"));
    caMan.setMode( CAManModeSelectCACert );

    if( caMan.exec() == QDialog::Accepted )
    {
        mIssuerNumText->setText( QString("%1").arg( caMan.getNum() ));
    }
}

void MakeCRLDlg::clickSelectProfile()
{
    ProfileManDlg profileMan;
    profileMan.setTitle( tr( "Select a profile" ));
    profileMan.setMode( ProfileManModeSelectCRLProfile );

    if( profileMan.exec() == QDialog::Accepted )
    {
        mProfileNumText->setText( QString("%1").arg(profileMan.getNum()));
    }
}

void MakeCRLDlg::clickViewProfile()
{
    QString strNum = mProfileNumText->text();
    if( strNum.length() < 1 )
    {
        manApplet->warningBox( tr("No profile selected"), this );
        return;
    }

    ViewCRLProfileDlg crlProfile;
    crlProfile.setProfile( strNum.toInt());
    crlProfile.exec();
}
