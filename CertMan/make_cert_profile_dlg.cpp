/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>
#include <QString>
#include <QDateTime>

#include "js_gen.h"
#include "js_pki_ext.h"
#include "make_cert_profile_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cert_profile_rec.h"
#include "profile_ext_rec.h"
#include "db_mgr.h"
#include "commons.h"
#include "settings_mgr.h"
#include "make_dn_dlg.h"
#include "man_tree_view.h"


static QStringList sExtNames = {
    "authorityInfoAccess",
    "authorityKeyIdentifier",
    "basicConstraints",
    "crlDistributionPoints",
    "extendedKeyUsage",
    "issuerAltName",
    "keyUsage",
    "nameConstraints",
    "certificatePolicies",
    "policyConstraints",
    "policyMappings",
    "subjectKeyIdentifier",
    "subjectAltName",
    "crlNumber",
    "issuingDistributionPoint",
    "CRLReason"
};

static QStringList kPeriodTypes = { "Day", "Month", "Year" };

MakeCertProfileDlg::MakeCertProfileDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mPolicySetAnyOIDBtn, SIGNAL(clicked()), this, SLOT(clickPolicySetAnyOID()));
    connect( mDaysTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeDaysType(int)));
    connect( mForCSRCheck, SIGNAL(clicked()), this, SLOT(checkForCSR()));
    connect( mMakeDNBtn, SIGNAL(clicked()), this, SLOT(clickMakeDN()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initUI();
    connectExtends();
    setExtends();
    setTableMenus();

    is_edit_ = false;
    profile_num_ = -1;
    mCertTab->setCurrentIndex(0);

    initialize();

    mNameText->setFocus();
    mCloseBtn->setFocus();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mBaseTab->layout()->setSpacing(5);
    mBaseTab->layout()->setMargin(5);

    mExtend1Tab->layout()->setSpacing(5);
    mExtend1Tab->layout()->setMargin(5);

    mExtend2Tab->layout()->setSpacing(5);
    mExtend2Tab->layout()->setMargin(5);

    mExtend3Tab->layout()->setSpacing(5);
    mExtend3Tab->layout()->setMargin(5);

    mExtend4Tab->layout()->setSpacing(5);
    mExtend4Tab->layout()->setMargin(5);

    mPeriodGroup->layout()->setSpacing(5);
    mPeriodGroup->layout()->setMargin(5);

    mExtensionsGroup->layout()->setSpacing(5);
    mExtensionsGroup->layout()->setMargin(5);

    mKeyUsageGroup->layout()->setSpacing(5);
    mKeyUsageGroup->layout()->setMargin(5);

    mPolicyGroup->layout()->setSpacing(5);
    mPolicyGroup->layout()->setMargin(5);

    mSKIGroup->layout()->setSpacing(5);
    mSKIGroup->layout()->setMargin(5);

    mAKIGroup->layout()->setSpacing(5);
    mAKIGroup->layout()->setMargin(5);

    mEKUGroup->layout()->setSpacing(5);
    mEKUGroup->layout()->setMargin(5);

    mCRLDPGroup->layout()->setSpacing(5);
    mCRLDPGroup->layout()->setMargin(5);

    mAIAGroup->layout()->setSpacing(5);
    mAIAGroup->layout()->setMargin(5);

    mBCGroup->layout()->setSpacing(5);
    mBCGroup->layout()->setMargin(5);

    mSANGroup->layout()->setSpacing(5);
    mSANGroup->layout()->setMargin(5);

    mIANGroup->layout()->setSpacing(5);
    mIANGroup->layout()->setMargin(5);

    mPCGroup->layout()->setSpacing(5);
    mPCGroup->layout()->setMargin(5);

    mPMGroup->layout()->setSpacing(5);
    mPMGroup->layout()->setMargin(5);

    mNCGroup->layout()->setSpacing(5);
    mNCGroup->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeCertProfileDlg::~MakeCertProfileDlg()
{

}

void MakeCertProfileDlg::setEdit(int nProfileNum )
{
    is_edit_ = true;

    setWindowTitle( tr( "Edit certificate profile" ));

    profile_num_ = nProfileNum;
    loadProfile( profile_num_ );
    mForCSRCheck->setEnabled(false);
}

void MakeCertProfileDlg::setReadOnly()
{
    setWindowTitle( tr( "View certificate profille" ));

    mNameText->setReadOnly(true);
}

void MakeCertProfileDlg::initialize()
{
    mCertTab->setCurrentIndex(0);
    mDaysTypeCombo->addItems( kPeriodTypes );

    defaultProfile();
}

void MakeCertProfileDlg::loadProfile( int nProfileNum, bool bCopy )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CertProfileRec certProfile;
    QDateTime notBefore;
    QDateTime notAfter;

    dbMgr->getCertProfileRec( nProfileNum, certProfile );

    if( bCopy == true )
        mNameText->setText( certProfile.getName() + "_Copy" );
    else
        mNameText->setText( certProfile.getName() );

    if( certProfile.getType() == JS_PKI_PROFILE_TYPE_CSR )
    {
        mVersionCombo->clear();
        mVersionCombo->addItem( "V1" );
        mForCSRCheck->setChecked( true );
    }
    else
    {
        mForCSRCheck->setChecked( false );
    }

    mVersionCombo->setCurrentIndex( certProfile.getVersion() );
    mHashCombo->setCurrentText( certProfile.getHash() );
    mSubjectDNText->setText( certProfile.getDNTemplate() );

    if( certProfile.getNotBefore() >= 0 && certProfile.getNotBefore() <= 2 )
    {
        mUseDaysCheck->setChecked(true);
        mDaysTypeCombo->setCurrentIndex( certProfile.getNotBefore() );
        mDaysText->setText( QString("%1").arg(certProfile.getNotAfter()));
    }
    else {
        mUseDaysCheck->setChecked(false);

        notBefore.setSecsSinceEpoch( certProfile.getNotBefore() );
        notAfter.setSecsSinceEpoch( certProfile.getNotAfter() );

        mNotBeforeDateTime->setDateTime( notBefore );
        mNotAfterDateTime->setDateTime( notAfter );
    }

    clickUseDays();

    if( certProfile.getDNTemplate() == kCSR_DN )
    {
        mUseCSR_DNCheck->setChecked(true);
    }
    else
    {
        mUseCSR_DNCheck->setChecked( false );
    }

    clickUseCSR_DN();

    mExtUsageCombo->setCurrentIndex( certProfile.getExtUsage() );

    QList<ProfileExtRec> extProfileList;
    dbMgr->getCertProfileExtensionList( nProfileNum, extProfileList );

    for( int i=0; i < extProfileList.size(); i++ )
    {
        ProfileExtRec extProfile = extProfileList.at(i);

        if( extProfile.getSN() == JS_PKI_ExtNameAIA )
            setAIAUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameAKI )
            setAKIUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameBC )
            setBCUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameCRLDP )
            setCRLDPUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameEKU )
            setEKUUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameIAN )
            setIANUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameKeyUsage )
            setKeyUsageUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameNC )
            setNCUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNamePolicy )
            setPolicyUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNamePC )
            setPCUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNamePM )
            setPMUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameSKI )
            setSKIUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameSAN )
            setSANUse( extProfile );
        else
            setExtensionsUse( extProfile );
    }

    checkForCSR();
}

void MakeCertProfileDlg::defaultProfile()
{
    int rowCnt = 0;
    mNameText->setText("");

    mVersionCombo->setCurrentIndex(2);
    mHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

    mAIAText->setText("");

    rowCnt = mAIATable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mAIATable->removeRow(0);


    mAIACriticalCheck->setChecked(false);


    mAKICriticalCheck->setChecked(false);
    mAKICertIssuerCheck->setChecked(false);
    mAKICertSerialCheck->setChecked(false);


    mBCCriticalCheck->setChecked(false);
    mBCPathLenText->setText("");

    rowCnt = mCRLDPTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mCRLDPTable->removeRow(0);


    mCRLDPCriticalCheck->setChecked(false);

    mEKUList->clear();

    mEKUCriticalCheck->setChecked(false);

    mIANCriticalCheck->setChecked(false);
    rowCnt = mIANTable->rowCount();
    for( int i = 0; i < rowCnt; i++ )
        mIANTable->removeRow(0);

    mKeyUsageList->clear();

    mKeyUsageCriticalCheck->setChecked(false);

    rowCnt = mNCTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mNCTable->removeRow(0);

    mNCCriticalCheck->setChecked(false);

    rowCnt = mPolicyTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mPolicyTable->removeRow(0);

    mPolicyCriticalCheck->setChecked(false);


    mPCCriticalCheck->setChecked(false);
    mPCInhibitText->setText("");
    mPCExplicitText->setText("");

    rowCnt = mPMTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mPMTable->removeRow(0);


    mPMCriticalCheck->setChecked(false);


    mSKICriticalCheck->setChecked(false);

    rowCnt = mSANTable->rowCount();
    for( int i = 0; i < rowCnt; i++ )
        mSANTable->removeRow(0);

    mSANCriticalCheck->setChecked(false);

    mUseCSR_DNCheck->setChecked(true);
    mSubjectDNText->setText( kCSR_DN );
    clickUseCSR_DN();

    mUseDaysCheck->setChecked(true);
    clickUseDays();

    mDaysText->setText( "365" );
}

void MakeCertProfileDlg::clickOK()
{
    int ret = 0;
    CertProfileRec certProfileRec;
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter a name"), this );
        mNameText->setFocus();
        return;
    }

    int nProfileNum = dbMgr->getCertProfileNextNum();
    if( nProfileNum <= 0 ) nProfileNum = 1;

    certProfileRec.setNum( nProfileNum );
    certProfileRec.setVersion( mVersionCombo->currentIndex() );
    certProfileRec.setName( strName );
    certProfileRec.setHash( mHashCombo->currentText() );

    if( mForCSRCheck->isChecked() )
    {
        certProfileRec.setType( JS_PKI_PROFILE_TYPE_CSR );
    }
    else
    {
        certProfileRec.setType( JS_PKI_PROFILE_TYPE_CERT );
        QString strSubjectDN;

        if( mUseCSR_DNCheck->isChecked() )
            strSubjectDN = kCSR_DN;
        else
            strSubjectDN = mSubjectDNText->text();

        if( strSubjectDN.isEmpty() )
        {
            manApplet->warningBox(tr( "Please enter a subject DN"), this );
            return;
        }

        certProfileRec.setDNTemplate( strSubjectDN );

        if( mUseDaysCheck->isChecked() )
        {
            certProfileRec.setNotBefore( mDaysTypeCombo->currentIndex() );
            certProfileRec.setNotAfter( mDaysText->text().toLong());
        }
        else {
            if( mNotBeforeDateTime->dateTime().toSecsSinceEpoch() <= 10 )
            {
                manApplet->warningBox( QString( tr("time is too early : %1").arg( mNotBeforeDateTime->dateTime().toSecsSinceEpoch())), this );
                return;
            }

            certProfileRec.setNotBefore( mNotBeforeDateTime->dateTime().toSecsSinceEpoch() );
            certProfileRec.setNotAfter( mNotAfterDateTime->dateTime().toSecsSinceEpoch() );
        }

        certProfileRec.setExtUsage( mExtUsageCombo->currentIndex() );
    }


    if( is_edit_ )
    {
        ret = dbMgr->modCertProfileRec( profile_num_, certProfileRec );
        if( ret != 0 ) goto end;

        dbMgr->delCertProfileExtensionList( profile_num_ );
        nProfileNum = profile_num_;

        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_MOD_CERT_PROFILE, "" );

    }
    else
    {
        ret = dbMgr->addCertProfileRec( certProfileRec );
        if( ret != 0 ) goto end;

        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_ADD_CERT_PROFILE, "" );

    }

    /* need to set extend fields here */
    saveAIAUse( nProfileNum );
    saveAKIUse( nProfileNum );
    saveBCUse( nProfileNum );
    saveCRLDPUse( nProfileNum );
    saveEKUUse( nProfileNum );
    saveIANUse( nProfileNum );
    saveKeyUsageUse( nProfileNum );
    saveNCUse( nProfileNum );
    savePolicyUse( nProfileNum );
    savePCUse( nProfileNum );
    savePMUse( nProfileNum );
    saveSKIUse( nProfileNum );
    saveSANUse( nProfileNum );
    saveExtensionsUse( nProfileNum );
    /* ....... */
end :
    if( ret == 0 )
    {
//        manApplet->mainWindow()->createRightCertProfileList();
        manApplet->mainWindow()->clickTreeMenu( CM_ITEM_TYPE_CERT_PROFILE );
        manApplet->messageBox( tr("Certificate profile created"), this );
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "failed to make certificate profile: %1").arg( JERR(ret)), this );
        QDialog::reject();
    }
}

void MakeCertProfileDlg::changeDaysType( int index )
{
    QString strType = mDaysTypeCombo->currentText();

    mDaysLabel->setText( strType.toLower() + "s" );
}

void MakeCertProfileDlg::changeBC()
{
    QString strBC = mBCCombo->currentText();

    if( strBC == "CA" )
    {
        mBCPathLenLabel->setEnabled( true );
        mBCPathLenText->setEnabled( true );
    }
    else
    {
        mBCPathLenLabel->setEnabled( false );
        mBCPathLenText->setEnabled( false );
    }
}

void MakeCertProfileDlg::initUI()
{
    static QStringList kExtUsageList = {
        tr("The Certificate Extension Only"),
        tr("The CSR Extension Only"),
        tr("Both Certificate and CSR and the The certificate first"),
        tr("Both Certificate and CSR and the CSR first")
    };

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    mExtend1Tab->setToolTip( "KeyUsage, Policy, SubjectKeyIdentifier, AuthorityKeyIdentifier" );
    mExtend2Tab->setToolTip( "ExtendKeyUsage, CRLDP, AuthorityInfoAccess" );
    mExtend3Tab->setToolTip( "BasicConstraints, SubjectAltName, IssuerAltName" );
    mExtend4Tab->setToolTip( "PolicyConstraints, PolicyMappings, NameConstraints" );

    mKeyUsageCombo->addItems(kKeyUsageList);
    mEKUCombo->addItems(kExtKeyUsageList);
    mVersionCombo->addItems(kCertVersionList);
    mCRLDPCombo->addItem( "URI" );
    mAIATargetCombo->addItems( kAIATargetList );
    mAIATypeCombo->addItem( "URI" );
    mSANCombo->addItems(kTypeList);
    mIANCombo->addItems(kTypeList);
    mNCTypeCombo->addItems(kNCTypeList);
    mNCSubCombo->addItems(kNCSubList);
    mBCCombo->addItems(kBCTypeList);
    mHashCombo->addItems(kHashList);
    mHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

    QDateTime nowDateTime;
    nowDateTime.setSecsSinceEpoch(time(NULL));
    mNotBeforeDateTime->setDateTime(nowDateTime);
    mNotAfterDateTime->setDateTime(nowDateTime);

    mExtUsageCombo->addItems( kExtUsageList );

    mExtensionsOIDText->setPlaceholderText( QString( "Object Identifier" ));
    mExtensionsValueText->setPlaceholderText( tr("Hex value" ));

    mPolicyOIDText->setPlaceholderText( QString( "Text OID" ));
    mPolicyCPSText->setPlaceholderText( tr("String value" ));
    mPolicyUserNoticeText->setPlaceholderText( tr( "String value" ));

    mCRLDPText->setPlaceholderText( tr( "URI address" ));
    mAIAText->setPlaceholderText( tr("URI address" ));

    mPMIssuerDomainPolicyText->setPlaceholderText( tr( "Text OID" ));
    mPMSubjectDomainPolicyText->setPlaceholderText( tr( "Text OID" ));
}

void MakeCertProfileDlg::setTableMenus()
{
    QStringList sPolicyLabels = { tr("OID"), tr("CPS"), tr("UserNotice") };
    mPolicyTable->setColumnCount(3);
    mPolicyTable->horizontalHeader()->setStretchLastSection(true);
    mPolicyTable->setHorizontalHeaderLabels( sPolicyLabels );
    mPolicyTable->verticalHeader()->setVisible(false);
    mPolicyTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mPolicyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mPolicyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPolicyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPolicyTable->setColumnWidth(0, 100);
    mPolicyTable->setColumnWidth(1, 100);


    QStringList sCRLDPLabels = { tr("Type"), tr("Value") };
    mCRLDPTable->setColumnCount(2);
    mCRLDPTable->horizontalHeader()->setStretchLastSection(true);
    mCRLDPTable->setHorizontalHeaderLabels(sCRLDPLabels);
    mCRLDPTable->verticalHeader()->setVisible(false);
    mCRLDPTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLDPTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mCRLDPTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLDPTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCRLDPTable->setColumnWidth(0,60);


    QStringList sAIALabels = { tr("Target"), tr("Type"), tr("Value") };
    mAIATable->setColumnCount(3);
    mAIATable->horizontalHeader()->setStretchLastSection(true);
    mAIATable->setHorizontalHeaderLabels(sAIALabels);
    mAIATable->verticalHeader()->setVisible(false);
    mAIATable->horizontalHeader()->setStyleSheet( kTableStyle );
    mAIATable->setSelectionMode(QAbstractItemView::SingleSelection);
    mAIATable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mAIATable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mAIATable->setColumnWidth(0,60);
    mAIATable->setColumnWidth(1,60);


    QStringList sSANLabels = { tr("Type"), tr("Value") };
    mSANTable->setColumnCount(2);
    mSANTable->horizontalHeader()->setStretchLastSection(true);
    mSANTable->setHorizontalHeaderLabels(sSANLabels);
    mSANTable->verticalHeader()->setVisible(false);
    mSANTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mSANTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mSANTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mSANTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mSANTable->setColumnWidth(0,60);


    QStringList sIANLabels = { tr("Type"), tr("Value") };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);
    mIANTable->verticalHeader()->setVisible(false);
    mIANTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mIANTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mIANTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIANTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mIANTable->setColumnWidth(0,60);


    QStringList sPMLabels = { tr("Target"), tr("Value"), tr("Target"), tr("Value") };
    mPMTable->setColumnCount(4);
    mPMTable->horizontalHeader()->setStretchLastSection(true);
    mPMTable->setHorizontalHeaderLabels(sPMLabels);
    mPMTable->verticalHeader()->setVisible(false);
    mPMTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mPMTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mPMTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPMTable->setEditTriggers(QAbstractItemView::NoEditTriggers);


    QStringList sNCLabels = { tr("Type"), tr("Target"), tr("Value"), tr("Min"), tr("Max") };
    mNCTable->setColumnCount(5);
    mNCTable->horizontalHeader()->setStretchLastSection(true);
    mNCTable->setHorizontalHeaderLabels(sNCLabels);
    mNCTable->verticalHeader()->setVisible(false);
    mNCTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mNCTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mNCTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mNCTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mNCTable->setColumnWidth(0,60);

    QStringList sExtensionsLabels = { tr("OID"), tr("Crit"), tr("Value") };
    mExtensionsTable->setColumnCount(sExtensionsLabels.size());
    mExtensionsTable->horizontalHeader()->setStretchLastSection(true);
    mExtensionsTable->setHorizontalHeaderLabels(sExtensionsLabels);
    mExtensionsTable->verticalHeader()->setVisible(false);
    mExtensionsTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mExtensionsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mExtensionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mExtensionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mExtensionsTable->setColumnWidth(0,180);
    mExtensionsTable->setColumnWidth(1,60);
}

void MakeCertProfileDlg::connectExtends()
{
    connect( mUseCSR_DNCheck, SIGNAL(clicked()), this, SLOT(clickUseCSR_DN()));
    connect( mUseDaysCheck, SIGNAL(clicked()), this, SLOT(clickUseDays()));

    connect( mBCCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeBC()));

    connect( mKeyUsageAddBtn, SIGNAL(clicked()), this, SLOT(addKeyUsage()));
    connect( mPolicyAddBtn, SIGNAL(clicked()), this, SLOT(addPolicy()));
    connect( mEKUAddBtn, SIGNAL(clicked()), this, SLOT(addEKU()));
    connect( mCRLDPAddBtn, SIGNAL(clicked()), this, SLOT(addCRLDP()));
    connect( mAIAAddBtn, SIGNAL(clicked()), this, SLOT(addAIA()));
    connect( mSANAddBtn, SIGNAL(clicked()), this, SLOT(addSAN()));
    connect( mIANAddBtn, SIGNAL(clicked()), this, SLOT(addIAN()));
    connect( mPMAddBtn, SIGNAL(clicked()), this, SLOT(addPM()));
    connect( mNCAddBtn, SIGNAL(clicked()), this, SLOT(addNC()));
    connect( mExtensionsAddBtn, SIGNAL(clicked()), this, SLOT(addExtensions()));

    connect( mKeyUsageClearBtn, SIGNAL(clicked()), this, SLOT(clearKeyUsage()));
    connect( mPolicyClearBtn, SIGNAL(clicked()), this, SLOT(clearPolicy()));
    connect( mEKUClearBtn, SIGNAL(clicked()), this, SLOT(clearEKU()));
    connect( mCRLDPClearBtn, SIGNAL(clicked()), this, SLOT(clearCRLDP()));
    connect( mAIAClearBtn, SIGNAL(clicked()), this, SLOT(clearAIA()));
    connect( mSANClearBtn, SIGNAL(clicked()), this, SLOT(clearSAN()));
    connect( mIANClearBtn, SIGNAL(clicked()), this, SLOT(clearIAN()));
    connect( mPMClearBtn, SIGNAL(clicked()), this, SLOT(clearPM()));
    connect( mNCClearBtn, SIGNAL(clicked()), this, SLOT(clearNC()));
    connect( mExtensionsClearBtn, SIGNAL(clicked()), this, SLOT(clearExtensions()));

    connect( mKeyUsageList, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotKeyUsageMenuRequested(QPoint)));
    connect( mEKUList, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotEKUMenuRequested(QPoint)));
    connect( mPolicyTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotPolicyMenuRequested(QPoint)));
    connect( mCRLDPTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotCRLDPMenuRequested(QPoint)));
    connect( mAIATable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotAIAMenuRequested(QPoint)));
    connect( mSANTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotSANMenuRequested(QPoint)));
    connect( mIANTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotIANMenuRequested(QPoint)));
    connect( mPMTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotPMMenuRequested(QPoint)));
    connect( mNCTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotNCMenuRequested(QPoint)));
    connect( mExtensionsTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotExtensionsMenuRequested(QPoint)));
}

void MakeCertProfileDlg::slotKeyUsageMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteKeyUsageMenu()));

    menu->addAction( delAct );
    menu->popup( mKeyUsageList->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteKeyUsageMenu()
{
    QModelIndex idx = mKeyUsageList->currentIndex();
    QListWidgetItem *item = mKeyUsageList->takeItem(idx.row());
    if( item ) delete item;
}

void MakeCertProfileDlg::slotEKUMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteEKUMenu()));

    menu->addAction( delAct );
    menu->popup( mEKUList->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteEKUMenu()
{
    QModelIndex idx = mEKUList->currentIndex();
    QListWidgetItem *item = mEKUList->takeItem(idx.row());
    if( item ) delete item;
}

void MakeCertProfileDlg::slotPolicyMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deletePolicyMenu()));

    menu->addAction( delAct );
    menu->popup( mPolicyTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deletePolicyMenu()
{
    QModelIndex idx = mPolicyTable->currentIndex();
    mPolicyTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::slotCRLDPMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteCRLDPMenu()));

    menu->addAction( delAct );
    menu->popup( mCRLDPTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteCRLDPMenu()
{
    QModelIndex idx = mCRLDPTable->currentIndex();
    mCRLDPTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::slotAIAMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteAIAMenu()));

    menu->addAction( delAct );
    menu->popup( mAIATable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteAIAMenu()
{
    QModelIndex idx = mAIATable->currentIndex();
    mAIATable->removeRow( idx.row() );
}

void MakeCertProfileDlg::slotSANMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteSANMenu()));

    menu->addAction( delAct );
    menu->popup( mSANTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteSANMenu()
{
    QModelIndex idx = mSANTable->currentIndex();
    mSANTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::slotIANMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteIANMenu()));

    menu->addAction( delAct );
    menu->popup( mIANTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteIANMenu()
{
    QModelIndex idx = mIANTable->currentIndex();
    mIANTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::slotPMMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deletePMMenu()));

    menu->addAction( delAct );
    menu->popup( mPMTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deletePMMenu()
{
    QModelIndex idx = mPMTable->currentIndex();
    mPMTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::slotNCMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteNCMenu()));

    menu->addAction( delAct );
    menu->popup( mNCTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::slotExtensionsMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteExtensionsMenu()));

    menu->addAction( delAct );
    menu->popup( mExtensionsTable->viewport()->mapToGlobal(pos));
}

void MakeCertProfileDlg::deleteExtensionsMenu()
{
    QModelIndex idx = mExtensionsTable->currentIndex();

    if( isEdit() )
    {
        DBMgr* dbMgr = manApplet->dbMgr();
        if( dbMgr == NULL ) return;
        QString strSN = mExtensionsTable->item( idx.row(), 0 )->text();
        ext_rmlist_.append( strSN );
    }

    mExtensionsTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::deleteNCMenu()
{
    QModelIndex idx = mNCTable->currentIndex();
    mNCTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::clickUseCSR_DN()
{
    if( mForCSRCheck->isChecked() == true )
    {
        mUseCSR_DNCheck->setEnabled( false );
        mSubjectDNLabel->setEnabled( false );
        mSubjectDNText->setEnabled( false );
        mMakeDNBtn->setEnabled( false );
    }
    else
    {
        bool bStatus = mUseCSR_DNCheck->isChecked();
        mSubjectDNLabel->setEnabled( true );
        mSubjectDNText->setEnabled( !bStatus );
        mMakeDNBtn->setEnabled( !bStatus );
    }
}

void MakeCertProfileDlg::clickUseDays()
{
    bool bStatus = mUseDaysCheck->isChecked();

    mDaysText->setEnabled(bStatus);
    mDaysTypeCombo->setEnabled(bStatus);
    mNotAfterDateTime->setEnabled(!bStatus);
    mNotBeforeDateTime->setEnabled(!bStatus);
}

void MakeCertProfileDlg::setExtends()
{
    clickUseCSR_DN();
    clickUseDays();
}




void MakeCertProfileDlg::addKeyUsage()
{
    int i = 0;
    QString strVal = mKeyUsageCombo->currentText();

    for( i = 0; i < mKeyUsageList->count(); i++ )
    {
        QListWidgetItem *item = mKeyUsageList->item(i);
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mKeyUsageList->insertItem( 0, strVal );
}

void MakeCertProfileDlg::addPolicy()
{
    QString strOID = mPolicyOIDText->text();
    QString strCPS = mPolicyCPSText->text();
    QString strUserNotice = mPolicyUserNoticeText->text();

    int row = mPolicyTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mPolicyTable->item( i, 0 );
        if( item->text() == strOID )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strOID ), this );
            return;
        }
    }

    mPolicyTable->insertRow(0);
    mPolicyTable->setRowHeight( 0, 10 );
    mPolicyTable->setItem( 0, 0, new QTableWidgetItem(strOID));
    mPolicyTable->setItem( 0, 1, new QTableWidgetItem(strCPS));
    mPolicyTable->setItem( 0, 2, new QTableWidgetItem(strUserNotice));

    mPolicyOIDText->clear();
    mPolicyCPSText->clear();
    mPolicyUserNoticeText->clear();
}

void MakeCertProfileDlg::addEKU()
{
    int i = 0;
    QString strVal = mEKUCombo->currentText();

    for( i = 0; i < mEKUList->count(); i++ )
    {
        QListWidgetItem *item = mEKUList->item(i);
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mEKUList->insertItem( 0, strVal );
}

void MakeCertProfileDlg::addCRLDP()
{
    QString strType = mCRLDPCombo->currentText();
    QString strVal = mCRLDPText->text();

    if( strVal.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter CRLDP value" ), this );
        return;
    }

    int row = mCRLDPTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mCRLDPTable->item( i, 1 );
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mCRLDPTable->insertRow(0);
    mCRLDPTable->setRowHeight( 0, 10 );
    mCRLDPTable->setItem( 0, 0, new QTableWidgetItem( strType ));
    mCRLDPTable->setItem( 0, 1, new QTableWidgetItem( strVal ));

    mCRLDPText->clear();
}

void MakeCertProfileDlg::addAIA()
{
    QString strTarget = mAIATargetCombo->currentText();
    QString strType = mAIATypeCombo->currentText();
    QString strVal = mAIAText->text();

    if( strVal.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter AuthorityInfoAccess value" ), this );
        return;
    }

    int row = mAIATable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mAIATable->item( i, 2 );
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mAIATable->insertRow(0);
    mAIATable->setRowHeight( 0, 10 );
    mAIATable->setItem( 0, 0, new QTableWidgetItem( strTarget ));
    mAIATable->setItem( 0, 1, new QTableWidgetItem( strType) );
    mAIATable->setItem( 0, 2, new QTableWidgetItem( strVal ));

    mAIAText->clear();
}

void MakeCertProfileDlg::addSAN()
{
    QString strType = mSANCombo->currentText();
    QString strVal = mSANText->text();

    if( strVal.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter Subject Alternative Name value" ), this );
        return;
    }

    int row = mSANTable->rowCount();
    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mSANTable->item( i, 1 );
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mSANTable->insertRow(0);
    mSANTable->setRowHeight( 0, 10 );
    mSANTable->setItem( 0, 0, new QTableWidgetItem(strType));
    mSANTable->setItem( 0, 1, new QTableWidgetItem(strVal));

    mSANText->clear();
}

void MakeCertProfileDlg::addIAN()
{
    QString strType = mIANCombo->currentText();
    QString strVal = mIANText->text();

    if( strVal.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter Issuer Alternative Name value" ), this );
        return;
    }

    int row = mIANTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mIANTable->item( i, 1 );
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mIANTable->insertRow(0);
    mIANTable->setRowHeight( 0, 10 );
    mIANTable->setItem( 0, 0, new QTableWidgetItem(strType));
    mIANTable->setItem( 0, 1, new QTableWidgetItem(strVal));

    mIANText->clear();
}

void MakeCertProfileDlg::addPM()
{
    QString strIDP = mPMIssuerDomainPolicyText->text();
    QString strSDP = mPMSubjectDomainPolicyText->text();

    if( strIDP.length() < 1 || strSDP.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter issuerDomainPolicy and subjectDomainPolicy both"), this );
        return;
    }

    if( strIDP == strSDP )
    {
        manApplet->warningBox( tr( "IssuerDomainPolicy and SubjectDomainPolicy must have different values" ), this );
        return;
    }

    int row = mPMTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mPMTable->item( i, 1 );
        if( item->text() == strIDP )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strIDP ), this );
            return;
        }
    }

    mPMTable->insertRow(0);
    mPMTable->setRowHeight( 0, 10 );
    mPMTable->setItem( 0, 0, new QTableWidgetItem( "IssuerDomainPolicy"));
    mPMTable->setItem( 0, 1, new QTableWidgetItem( strIDP));
    mPMTable->setItem( 0, 2, new QTableWidgetItem( "SubjectDomainPolicy"));
    mPMTable->setItem( 0, 3, new QTableWidgetItem( strSDP));

    mPMIssuerDomainPolicyText->clear();
    mPMSubjectDomainPolicyText->clear();
}

void MakeCertProfileDlg::addNC()
{
    QString strType = mNCTypeCombo->currentText();
    QString strSubType = mNCSubCombo->currentText();
    QString strVal = mNCSubText->text();
    QString strMax = mNCMaxText->text();
    QString strMin = mNCMinText->text();

    if( strVal.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter Name Constraints value" ), this );
        return;
    }

    int row = mNCTable->rowCount();
    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mNCTable->item( i, 2 );
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mNCTable->insertRow(0);
    mNCTable->setRowHeight( 0, 10 );
    mNCTable->setItem( 0, 0, new QTableWidgetItem(strType));
    mNCTable->setItem( 0, 1, new QTableWidgetItem(strSubType));
    mNCTable->setItem( 0, 2, new QTableWidgetItem(strVal));
    mNCTable->setItem( 0, 3, new QTableWidgetItem(strMin));
    mNCTable->setItem( 0, 4, new QTableWidgetItem(strMax));

    mNCSubText->clear();
    mNCMinText->clear();
    mNCMaxText->clear();
}

void MakeCertProfileDlg::addExtensions()
{
    QString strOID = mExtensionsOIDText->text();
    QString strValue = mExtensionsValueText->toPlainText();
    bool bCrit = mExtensionsCriticalCheck->isChecked();
    QString strCrit;

    if( strOID.length() < 1 || strValue.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter OID and Value both"), this );
        return;
    }

    if( bCrit )
        strCrit = kTrue;
    else
        strCrit = kFalse;

    int row = mExtensionsTable->rowCount();

    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mExtensionsTable->item( i, 0 );
        if( item->text() == strOID )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strOID ), this );
            return;
        }
    }

    mExtensionsTable->insertRow(0);
    mExtensionsTable->setRowHeight( 0, 10 );
    mExtensionsTable->setItem( 0, 0, new QTableWidgetItem(strOID));
    mExtensionsTable->setItem( 0, 1, new QTableWidgetItem(strCrit));
    mExtensionsTable->setItem( 0, 2, new QTableWidgetItem(strValue));

    mExtensionsOIDText->clear();
    mExtensionsValueText->clear();
}

void MakeCertProfileDlg::clearKeyUsage()
{
    mKeyUsageList->clear();
}

void MakeCertProfileDlg::clearPolicy()
{
    int nCnt = mPolicyTable->rowCount();

    for( int i=0; i < nCnt; i++ )
        mPolicyTable->removeRow(0);
}

void MakeCertProfileDlg::clearEKU()
{
    mEKUList->clear();
}

void MakeCertProfileDlg::clearCRLDP()
{
    int nCnt = mCRLDPTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mCRLDPTable->removeRow(0);
}

void MakeCertProfileDlg::clearAIA()
{
    int nCnt = mAIATable->rowCount();

    for( int i=0; i < nCnt; i++)
        mAIATable->removeRow(0);
}

void MakeCertProfileDlg::clearSAN()
{
    int nCnt = mSANTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mSANTable->removeRow(0);
}

void MakeCertProfileDlg::clearIAN()
{
    int nCnt = mIANTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mIANTable->removeRow(0);
}

void MakeCertProfileDlg::clearPM()
{
    int nCnt = mPMTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mPMTable->removeRow(0);
}

void MakeCertProfileDlg::clearNC()
{
    int nCnt = mNCTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mNCTable->removeRow(0);
}

void MakeCertProfileDlg::clearExtensions()
{
    int nCount = mExtensionsTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        if( isEdit() )
        {
            QString strSN = mExtensionsTable->item( 0, 0 )->text();
            ext_rmlist_.append( strSN );
        }

        mExtensionsTable->removeRow(0);
    }
}

void MakeCertProfileDlg::clickPolicySetAnyOID()
{
    mPolicyOIDText->setText( "2.5.29.32.0" );
}

void MakeCertProfileDlg::checkForCSR()
{
    bool bVal = mForCSRCheck->isChecked();

    mVersionLabel->setEnabled( !bVal );
    mVersionCombo->setEnabled( !bVal );
    mHashLabel->setEnabled( !bVal );
    mHashCombo->setEnabled( !bVal );
    mPeriodGroup->setEnabled( !bVal );

/*
    mNotAfterDateTime->setEnabled( !bVal );
    mNotBeforeDateTime->setEnabled( !bVal );
    mUseDaysCheck->setEnabled( !bVal );

    mDaysLabel->setEnabled( !bVal );
    mDaysTypeCombo->setEnabled( !bVal );
    mDaysText->setEnabled( !bVal );
*/

    mUseCSR_DNCheck->setEnabled( !bVal );

    clickUseCSR_DN();
    mExtUsageLabel->setEnabled( !bVal );
    mExtUsageCombo->setEnabled( !bVal );
}

void MakeCertProfileDlg::clickMakeDN()
{
    QString strDN = mSubjectDNText->text();

    MakeDNDlg makeDNDlg;
    makeDNDlg.setDN( strDN );

    if( makeDNDlg.exec() == QDialog::Accepted )
    {
        QString strDN = makeDNDlg.getDN();
        mSubjectDNText->setText( strDN );
    }
}

void MakeCertProfileDlg::saveAIAUse(int nProfileNum )
{
    int nAIACnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameAIA );
    if( mAIAGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameAIA );
    profileExt.setCritical( mAIACriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mAIATable->rowCount(); i++ )
    {
        QString strMethod;
        QString strType;
        QString strData;

        strMethod = mAIATable->takeItem( i, 0 )->text();
        strType = mAIATable->takeItem( i, 1)->text();
        strData = mAIATable->takeItem( i, 2 )->text();

        if( strData.length() < 1 ) continue;

        if( i != 0 ) strVal += "#";
        strVal += strMethod;
        strVal += "$";
        strVal += strType;
        strVal += "$";
        strVal += strData;

        nAIACnt++;
    }

    if( nAIACnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension(profileExt);
    }
}

void MakeCertProfileDlg::saveAKIUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameAKI );
    if( mAKIGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameAKI );
    profileExt.setCritical( mAKICriticalCheck->isChecked() );

    QString strVal;

    if( mAKICertIssuerCheck->isChecked() ) strVal += "ISSUER#";
    if( mAKICertSerialCheck->isChecked() ) strVal += "SERIAL#";

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveBCUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameBC );
    if( mBCGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN(JS_PKI_ExtNameBC);
    profileExt.setCritical( mBCCriticalCheck->isChecked() );

    QString strVal;

    if( mBCCombo->currentIndex() == 0 )
        strVal = "CA";
    else {
        strVal = "EE";
    }

    if( mBCPathLenText->text().length() > 0 )
    {
        strVal += "#";
        strVal += mBCPathLenText->text();
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveCRLDPUse(int nProfileNum )
{
    int nCRLDPCnt = 0;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameCRLDP );
    if( mCRLDPGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameCRLDP );
    profileExt.setCritical( mCRLDPCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mCRLDPTable->rowCount(); i++ )
    {
        QString strType = "";
        QString strData = "";

        strType = mCRLDPTable->takeItem( i, 0 )->text();
        strData = mCRLDPTable->takeItem( i, 1 )->text();

        if( strData.length() < 1 ) continue;

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;

        nCRLDPCnt++;
    }

    if( nCRLDPCnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::saveEKUUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameEKU );
    if( mEKUGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameEKU);
    profileExt.setCritical( mEKUCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mEKUList->count(); i++ )
    {
        QString strCur = mEKUList->item(i)->text();

        if( strCur.length() > 0 )
        {
            if( strVal.length() > 0 ) strVal += "#";

            strVal += strCur;
        }
    }

    if( strVal.length() > 1 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::saveIANUse(int nProfileNum )
{
    int nIANCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameIAN );
    if( mIANGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameIAN );
    profileExt.setCritical( mIANCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; i < mIANTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mIANTable->takeItem( i, 0)->text();
        strData = mIANTable->takeItem( i, 1)->text();

        if( strData.length() < 1 ) continue;

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;

        nIANCnt++;
    }

    if( nIANCnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::saveKeyUsageUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameKeyUsage );
    if( mKeyUsageGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameKeyUsage );
    profileExt.setCritical( mKeyUsageCriticalCheck->isChecked() );

    QString strValue;

    for( int i =0; i < mKeyUsageList->count(); i++ )
    {
        QString strCur = mKeyUsageList->item(i)->text();
        if( strCur.length() > 0 )
        {
            if( strValue.length() > 0 ) strValue += "#";

            strValue += strCur;
        }
    }

    if( strValue.length() > 1 )
    {
        profileExt.setValue( strValue );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::saveNCUse(int nProfileNum )
{
    int nNCCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameNC );
    if( mNCGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameNC );
    profileExt.setCritical( mNCCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mNCTable->rowCount(); i++ )
    {
        QString strType;
        QString strKind;
        QString strData;
        QString strMin;
        QString strMax;

        strType = mNCTable->takeItem( i, 0 )->text();
        strKind = mNCTable->takeItem(i, 1)->text();
        strData = mNCTable->takeItem(i, 2)->text();
        strMin = mNCTable->takeItem(i,3)->text();
        strMax = mNCTable->takeItem(i,4)->text();

        if( strData.length() < 1 ) continue;

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strKind;
        strVal += "$";
        strVal += strData;
        strVal += "$";
        strVal += strMin;
        strVal += "$";
        strVal += strMax;

        nNCCnt++;
    }

    if( nNCCnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::savePolicyUse(int nProfileNum )
{
    int nPolicyCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNamePolicy );
    if( mPolicyGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNamePolicy );
    profileExt.setCritical( mPolicyCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; i < mPolicyTable->rowCount(); i++ )
    {
        if( i != 0 ) strVal += "%%";

        QString strOID = mPolicyTable->takeItem(i,0)->text();
        QString strCPS = mPolicyTable->takeItem(i,1)->text();
        QString strUserNotice = mPolicyTable->takeItem(i,2)->text();

        if( strOID.length() < 1 ) continue;

        strVal += "OID$";
        strVal += strOID;
        strVal += "#CPS$";
        strVal += strCPS;
        strVal += "#UserNotice$";
        strVal += strUserNotice;
        strVal += "#";
        nPolicyCnt++;
    }

    if( nPolicyCnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::savePCUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNamePC );
    if( mPCGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNamePC );
    profileExt.setCritical( mPCCriticalCheck->isChecked() );

    QString strVal;
    strVal = "REP";

    if( mPCExplicitText->text().length() > 0 )
    {
        strVal += "$";
        strVal += mPCExplicitText->text();
    }

    strVal += "#IPM";
    if( mPCInhibitText->text().length() > 0 )
    {
        strVal += "$";
        strVal += mPCInhibitText->text();
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension(profileExt);
}

void MakeCertProfileDlg::savePMUse(int nProfileNum )
{
    int nPMCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNamePM );
    if( mPMGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNamePM );
    profileExt.setCritical( mPMCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; i < mPMTable->rowCount(); i++ )
    {
        QString strIDP;
        QString strSDP;

        strIDP = mPMTable->takeItem(i, 1)->text();
        strSDP = mPMTable->takeItem(i, 3)->text();

        if( strIDP.length() < 1 && strSDP.length() < 1 )
            continue;

        if( i != 0 ) strVal += "#";
        strVal += strIDP;
        strVal += "$";
        strVal += strSDP;

        nPMCnt++;
    }

    if( nPMCnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::saveSKIUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameSKI );
    if( mSKIGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameSKI );
    profileExt.setCritical( mSKICriticalCheck->isChecked() );

    dbMgr->addCertProfileExtension(profileExt);
}

void MakeCertProfileDlg::saveSANUse(int nProfileNum)
{
    int nSANCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, JS_PKI_ExtNameSAN );
    if( mSANGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameSAN );
    profileExt.setCritical( mSANCriticalCheck->isChecked() );

    QString strVal = "";
    for( int i=0; i < mSANTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mSANTable->takeItem( i, 0 )->text();
        strData = mSANTable->takeItem( i, 1 )->text();

        if( strData.length() < 1 ) continue;

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;

        nSANCnt++;
    }

    if( nSANCnt > 0 )
    {
        profileExt.setValue( strVal );
        dbMgr->addCertProfileExtension( profileExt );
    }
}

void MakeCertProfileDlg::saveExtensionsUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    int nCount = mExtensionsTable->rowCount();

    if( isEdit() )
    {
        int size = ext_rmlist_.size();
        for( int i = 0; i < size; i++ )
        {
            QString strSN = ext_rmlist_.at(i);
            dbMgr->delCertProfileExtension( profile_num_, strSN );
        }

        ext_rmlist_.clear();
    }

    for( int i = 0; i < nCount; i++ )
    {
        bool bCrit = false;
        QString strOID = mExtensionsTable->takeItem( i, 0 )->text();
        QString strCrit = mExtensionsTable->takeItem( i, 1 )->text();
        QString strValue = mExtensionsTable->takeItem( i, 2)->text();

        if( strCrit == kTrue ) bCrit = true;

        ProfileExtRec profileRec;
        profileRec.setProfileNum( nProfileNum );
        profileRec.setSN( strOID );
        profileRec.setValue( strValue );
        profileRec.setCritical( bCrit );

        if( isEdit() ) dbMgr->delCertProfileExtension( profile_num_, profileRec.getSN() );
        dbMgr->addCertProfileExtension( profileRec );
    }
}

void MakeCertProfileDlg::setAIAUse( ProfileExtRec& profileRec )
{
    mAIAGroup->setChecked(true);
    mAIACriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QString strMethod = "";
        QString strType = "";
        QString strData = "";

        QStringList infoList = info.split("$");

        if( infoList.size() < 3 ) continue;

        strMethod = infoList.at(0);
        strType = infoList.at(1);
        strData = infoList.at(2);

        mAIATable->insertRow(i);
        mAIATable->setRowHeight(i,10);
        mAIATable->setItem( i, 0, new QTableWidgetItem(strMethod));
        mAIATable->setItem( i, 1, new QTableWidgetItem(strType));
        mAIATable->setItem( i, 2, new QTableWidgetItem(strData));

        mAIATable->item( i, 2 )->setToolTip( strData );
    }
}

void MakeCertProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    mAKIGroup->setChecked(true);
    mAKICriticalCheck->setChecked( profileRec.isCritical() );


    QString strVal = profileRec.getValue();

    bool bStatus = strVal.contains("ISSUER");
    mAKICertIssuerCheck->setChecked(bStatus);

    bStatus = strVal.contains("SERIAL");
    mAKICertSerialCheck->setChecked(bStatus);
}

void MakeCertProfileDlg::setBCUse( ProfileExtRec& profileRec )
{
    mBCGroup->setChecked(true);
    mBCCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();
    QString strType;
    QString strLen;

    QStringList valList = strVal.split("#");

    if( valList.size() >= 1 )
        strType= valList.at(0);

    if( valList.size() >= 2 )
        strLen = valList.at(1);

    if( strType == "CA" )
        mBCCombo->setCurrentIndex(0);
    else
        mBCCombo->setCurrentIndex(1);

    mBCPathLenText->setText( strLen );
}

void MakeCertProfileDlg::setCRLDPUse( ProfileExtRec& profileRec )
{
    mCRLDPGroup->setChecked(true);
    mCRLDPCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList typeData = info.split("$");

        if( typeData.size() < 2 ) continue;

        QString strType = typeData.at(0);
        QString strData = typeData.at(1);

        mCRLDPTable->insertRow(i);
        mCRLDPTable->setRowHeight( i, 10 );
        mCRLDPTable->setItem( i, 0, new QTableWidgetItem(strType));
        mCRLDPTable->setItem( i, 1, new QTableWidgetItem(strData));

        mCRLDPTable->item( i, 1 )->setToolTip( strData );
    }
}

void MakeCertProfileDlg::setEKUUse( ProfileExtRec& profileRec )
{
    QString strVal = "";

    mEKUGroup->setChecked(true);
    mEKUCriticalCheck->setChecked(profileRec.isCritical());


    strVal = profileRec.getValue();
    QStringList valList = strVal.split("#");

    if( valList.size() > 0 ) mEKUList->insertItems( 0, valList );
}

void MakeCertProfileDlg::setIANUse( ProfileExtRec& profileRec )
{
    mIANGroup->setChecked(true);
    mIANCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        if( infoList.size() < 2 ) continue;

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mIANTable->insertRow(i);
        mIANTable->setRowHeight( i, 10 );
        mIANTable->setItem( i, 0, new QTableWidgetItem(strType));
        mIANTable->setItem(i, 1, new QTableWidgetItem(strData));

        mIANTable->item( i, 1 )->setToolTip( strData );
    }
}

void MakeCertProfileDlg::setKeyUsageUse( ProfileExtRec& profileRec )
{
    mKeyUsageGroup->setChecked(true);
    mKeyUsageCriticalCheck->setChecked( profileRec.isCritical() );


    QString strVal = profileRec.getValue();

    mKeyUsageList->clear();

    QStringList valList = strVal.split("#");
    if( valList.size() > 0 ) mKeyUsageList->insertItems(0, valList );
}

void MakeCertProfileDlg::setNCUse( ProfileExtRec& profileRec )
{
    mNCGroup->setChecked(true);
    mNCCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        QString strType = infoList.at(0);
        QString strKind = infoList.at(1);
        QString strData = infoList.at(2);
        QString strMin;
        QString strMax;

        if( infoList.size() > 3 ) strMin = infoList.at(3);
        if( infoList.size() > 4 ) strMax = infoList.at(4);

        mNCTable->insertRow(i);
        mNCTable->setRowHeight( i, 10 );
        mNCTable->setItem(i, 0, new QTableWidgetItem(strType));
        mNCTable->setItem(i, 1, new QTableWidgetItem(strKind));
        mNCTable->setItem(i, 2, new QTableWidgetItem(strData));
        mNCTable->setItem(i, 3, new QTableWidgetItem(strMin));
        mNCTable->setItem(i, 4, new QTableWidgetItem(strMax));
    }
}

void MakeCertProfileDlg::setPolicyUse( ProfileExtRec& profileRec )
{
    mPolicyGroup->setChecked(true);
    mPolicyCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("%%");

    for( int i=0; i < valList.size(); i++ )
    {
        QString strInfo = valList.at(i);
        QStringList infoList = strInfo.split("#");
        QString strOID = "";
        QString strCPS = "";
        QString strUserNotice = "";

        for( int k = 0; k < infoList.size(); k++ )
        {
            QString info = infoList.at(k);
            QStringList typeData = info.split("$");

            if( typeData.size() < 2 ) continue;

            QString strType = typeData.at(0);
            QString strData = typeData.at(1);

            if( strType == "OID" )
                strOID = strData;
            else if( strType == "CPS" )
                strCPS = strData;
            else if( strType == "UserNotice" )
                strUserNotice = strData;
        }

        int row = mPolicyTable->rowCount();

        mPolicyTable->setRowCount( row + 1 );

        mPolicyTable->setRowHeight( row, 10 );
        mPolicyTable->setItem( row, 0, new QTableWidgetItem(strOID));
        mPolicyTable->setItem( row, 1, new QTableWidgetItem(strCPS));
        mPolicyTable->setItem( row, 2, new QTableWidgetItem(strUserNotice));

        mPolicyTable->item( row, 0 )->setToolTip( strOID );
        mPolicyTable->item( row, 1 )->setToolTip( strCPS );
        mPolicyTable->item( row, 2 )->setToolTip( strUserNotice );
    }
}

void MakeCertProfileDlg::setPCUse( ProfileExtRec& profileRec )
{
    mPCGroup->setChecked(true);
    mPCCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();
    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        if( infoList.size() < 2 ) continue;

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        if( strType == "REP" )
            mPCExplicitText->setText( strData );
        else if( strType == "IPM" )
            mPCInhibitText->setText( strData );
    }
}

void MakeCertProfileDlg::setPMUse( ProfileExtRec& profileRec )
{
    mPMGroup->setChecked(true);
    mPMCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        if( infoList.size() < 2 ) continue;

        QString strIDP = infoList.at(0);
        QString strSDP = infoList.at(1);

        mPMTable->insertRow(i);
        mPMTable->setRowHeight( i, 10 );
        mPMTable->setItem(i,0,new QTableWidgetItem("issuerDomainPolicy"));
        mPMTable->setItem(i,1,new QTableWidgetItem(strIDP));
        mPMTable->setItem(i,2,new QTableWidgetItem("subjectDomainPolicy"));
        mPMTable->setItem(i,3,new QTableWidgetItem(strSDP));
    }
}

void MakeCertProfileDlg::setSKIUse( ProfileExtRec& profileRec )
{
    mSKIGroup->setChecked(true);
    mSKICriticalCheck->setChecked(profileRec.isCritical());
}

void MakeCertProfileDlg::setSANUse( ProfileExtRec& profileRec )
{
    mSANGroup->setChecked(true);
    mSANCriticalCheck->setChecked(profileRec.isCritical());


    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mSANTable->insertRow(i);
        mSANTable->setRowHeight( i, 10 );
        mSANTable->setItem( i, 0, new QTableWidgetItem(strType));
        mSANTable->setItem(i, 1, new QTableWidgetItem(strData));

        mSANTable->item( i, 1 )->setToolTip( strData );
    }
}

void MakeCertProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{
    QString strOID = profileRec.getSN();
    QString strValue = profileRec.getValue();
    QString strCrit;

    if( profileRec.isCritical() )
        strCrit = kTrue;
    else
        strCrit = kFalse;

    int row = mExtensionsTable->rowCount();
    mExtensionsTable->setRowCount( row + 1 );
    mExtensionsTable->setRowHeight( row, 10 );
    mExtensionsTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mExtensionsTable->setItem( row, 1, new QTableWidgetItem(strCrit));
    mExtensionsTable->setItem( row, 2, new QTableWidgetItem(strValue));
}
