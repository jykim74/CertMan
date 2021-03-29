#include <QMenu>

#include "make_cert_profile_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cert_profile_rec.h"
#include "profile_ext_rec.h"
#include "db_mgr.h"
#include "commons.h"


MakeCertProfileDlg::MakeCertProfileDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    connectExtends();
    setExtends();
    setTableMenus();

    is_edit_ = false;
    profile_num_ = -1;
    mCertTab->setCurrentIndex(0);
}

MakeCertProfileDlg::~MakeCertProfileDlg()
{

}

void MakeCertProfileDlg::setEdit(bool is_edit)
{
    is_edit_ = is_edit;
}

void MakeCertProfileDlg::setProfileNum(int profile_num)
{
    profile_num_ = profile_num;
}

void MakeCertProfileDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void MakeCertProfileDlg::initialize()
{
    mCertTab->setCurrentIndex(0);

    if( is_edit_ )
        loadProfile();
    else
        defaultProfile();
}

void MakeCertProfileDlg::loadProfile()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CertProfileRec certProfile;
    QDateTime notBefore;
    QDateTime notAfter;

    dbMgr->getCertProfileRec( profile_num_, certProfile );

    mNameText->setText( certProfile.getName() );
    mVersionCombo->setCurrentIndex( certProfile.getVersion() );
    mHashCombo->setCurrentText( certProfile.getHash() );
    mSubjectDNText->setText( certProfile.getDNTemplate() );

    if( certProfile.getNotBefore() == 0 )
    {
        mUseDaysCheck->setChecked(true);
        mDaysText->setText( QString("%1").arg(certProfile.getNotAfter()));
    }
    else {
        notBefore.setTime_t( certProfile.getNotBefore() );
        notAfter.setTime_t( certProfile.getNotAfter() );

        mNotBeforeDateTime->setDateTime( notBefore );
        mNotAfterDateTime->setDateTime( notAfter );
    }

    clickUseDays();

    if( certProfile.getDNTemplate() == "#CSR" )
    {
        mUseCSRCheck->setChecked(true);
        clickUseCSR();
    }


    QList<ProfileExtRec> extProfileList;
    dbMgr->getCertProfileExtensionList( profile_num_, extProfileList );

    for( int i=0; i < extProfileList.size(); i++ )
    {
        ProfileExtRec extProfile = extProfileList.at(i);

        if( extProfile.getSN() == kExtNameAIA )
            setAIAUse( extProfile );
        else if( extProfile.getSN() == kExtNameAKI )
            setAKIUse( extProfile );
        else if( extProfile.getSN() == kExtNameBC )
            setBCUse( extProfile );
        else if( extProfile.getSN() == kExtNameCRLDP )
            setCRLDPUse( extProfile );
        else if( extProfile.getSN() == kExtNameEKU )
            setEKUUse( extProfile );
        else if( extProfile.getSN() == kExtNameIAN )
            setIANUse( extProfile );
        else if( extProfile.getSN() == kExtNameKeyUsage )
            setKeyUsageUse( extProfile );
        else if( extProfile.getSN() == kExtNameNC )
            setNCUse( extProfile );
        else if( extProfile.getSN() == kExtNamePolicy )
            setPolicyUse( extProfile );
        else if( extProfile.getSN() == kExtNamePC )
            setPCUse( extProfile );
        else if( extProfile.getSN() == kExtNamePM )
            setPMUse( extProfile );
        else if( extProfile.getSN() == kExtNameSKI )
            setSKIUse( extProfile );
        else if( extProfile.getSN() == kExtNameSAN )
            setSANUse( extProfile );
    }

}

void MakeCertProfileDlg::defaultProfile()
{
    int rowCnt = 0;
    mNameText->setText("");

    mVersionCombo->setCurrentIndex(2);
    mHashCombo->setCurrentIndex(2);

    mAIAText->setText("");

    rowCnt = mAIATable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mAIATable->removeRow(0);

    mAIAUseCheck->setChecked(false);
    mAIACriticalCheck->setChecked(false);

    mAKIUseCheck->setChecked(false);
    mAKICriticalCheck->setChecked(false);
    mAKICertIssuerCheck->setChecked(false);
    mAKICertSerialCheck->setChecked(false);

    mBCUseCheck->setChecked(false);
    mBCCriticalCheck->setChecked(false);
    mBCPathLenText->setText("");

    rowCnt = mCRLDPTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mCRLDPTable->removeRow(0);

    mCRLDPUseCheck->setChecked(false);
    mCRLDPCriticalCheck->setChecked(false);

    mEKUList->clear();
    mEKUUseCheck->setChecked(false);
    mEKUCriticalCheck->setChecked(false);

    mIANUseCheck->setChecked(false);
    mIANCriticalCheck->setChecked(false);
    rowCnt = mIANTable->rowCount();
    for( int i = 0; i < rowCnt; i++ )
        mIANTable->removeRow(0);

    mKeyUsageList->clear();
    mKeyUsageUseCheck->setChecked(false);
    mKeyUsageCriticalCheck->setChecked(false);

    rowCnt = mNCTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mNCTable->removeRow(0);
    mNCUseCheck->setChecked(false);
    mNCCriticalCheck->setChecked(false);

    rowCnt = mPolicyTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mPolicyTable->removeRow(0);
    mPolicyUseCheck->setChecked(false);
    mPolicyCriticalCheck->setChecked(false);

    mPCUseCheck->setChecked(false);
    mPCCriticalCheck->setChecked(false);
    mPCInhibitText->setText("");
    mPCExplicitText->setText("");

    rowCnt = mPMTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mPMTable->removeRow(0);

    mPMUseCheck->setChecked(false);
    mPMCriticalCheck->setChecked(false);

    mSKIUseCheck->setChecked(false);
    mSKICriticalCheck->setChecked(false);

    rowCnt = mSANTable->rowCount();
    for( int i = 0; i < rowCnt; i++ )
        mSANTable->removeRow(0);
    mSANUseCheck->setChecked(false);
    mSANCriticalCheck->setChecked(false);

    mUseCSRCheck->setChecked(true);
    clickUseCSR();

    mUseDaysCheck->setChecked(true);
    clickUseDays();

    mDaysText->setText( "365" );
}

void MakeCertProfileDlg::accept()
{
    CertProfileRec certProfileRec;
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to insert name"), this );
        mNameText->setFocus();
        return;
    }

    QString strSubjectDN = mSubjectDNText->text();
    if( strSubjectDN.isEmpty() )
    {
        manApplet->warningBox(tr( "You have to set subjec dn"), this );
        return;
    }

    int nProfileNum = dbMgr->getCertProfileNextNum();

    certProfileRec.setNum( nProfileNum );
    certProfileRec.setVersion( mVersionCombo->currentIndex() );
    certProfileRec.setName( strName );
    certProfileRec.setDNTemplate( strSubjectDN );

    if( mUseDaysCheck->isChecked() )
    {
        certProfileRec.setNotBefore(0);
        certProfileRec.setNotAfter( mDaysText->text().toLong());
    }
    else {
        QDateTime beforeTime;
        QDateTime afterTime;

        beforeTime.setDate( mNotBeforeDateTime->date() );
        afterTime.setDate( mNotAfterDateTime->date() );

        certProfileRec.setNotBefore( beforeTime.toTime_t() );
        certProfileRec.setNotAfter( afterTime.toTime_t() );
    }

    certProfileRec.setHash( mHashCombo->currentText() );

    if( is_edit_ )
    {
        dbMgr->modCertProfileRec( profile_num_, certProfileRec );
        dbMgr->delCertProfileExtensionList( profile_num_ );
        nProfileNum = profile_num_;
    }
    else
    {
        dbMgr->addCertProfileRec( certProfileRec );
    }

    /* need to set extend fields here */
    if( mAIAUseCheck->isChecked() ) saveAIAUse( nProfileNum );
    if( mAKIUseCheck->isChecked() ) saveAKIUse( nProfileNum );
    if( mBCUseCheck->isChecked() ) saveBCUse( nProfileNum );
    if( mCRLDPUseCheck->isChecked() ) saveCRLDPUse( nProfileNum );
    if( mEKUUseCheck->isChecked() ) saveEKUUse( nProfileNum );
    if( mIANUseCheck->isChecked() ) saveIANUse( nProfileNum );
    if( mKeyUsageUseCheck->isChecked() ) saveKeyUsageUse( nProfileNum );
    if( mNCUseCheck->isChecked() ) saveNCUse( nProfileNum );
    if( mPolicyUseCheck->isChecked() ) savePolicyUse( nProfileNum );
    if( mPCUseCheck->isChecked() ) savePCUse( nProfileNum );
    if( mPMUseCheck->isChecked() ) savePMUse( nProfileNum );
    if( mSKIUseCheck->isChecked() ) saveSKIUse( nProfileNum );
    if( mSANUseCheck->isChecked() ) saveSANUse( nProfileNum );
    /* ....... */

    manApplet->mainWindow()->createRightCertProfileList();
    QDialog::accept();
}

void MakeCertProfileDlg::initUI()
{
    mKeyUsageCombo->addItems(kKeyUsageList);
    mEKUCombo->addItems(kExtKeyUsageList);
    mVersionCombo->addItems(kCertVersionList);
//    mCRLDPCombo->addItems(kTypeList);
    mCRLDPCombo->addItem( "URI" );
    mAIATargetCombo->addItems( kAIATargetList );
//    mAIATypeCombo->addItems(kTypeList);
    mAIATypeCombo->addItem( "URI" );
    mSANCombo->addItems(kTypeList);
    mIANCombo->addItems(kTypeList);
//    mNCTypeCombo->addItems(kTypeList);
    mNCTypeCombo->addItem( "URI" );
    mNCSubCombo->addItems(kNCSubList);
    mBCCombo->addItems(kBCTypeList);
    mHashCombo->addItems(kHashList);

    QDateTime nowDateTime;
    nowDateTime.setTime_t(time(NULL));
    mNotBeforeDateTime->setDateTime(nowDateTime);
    mNotAfterDateTime->setDateTime(nowDateTime);
}

void MakeCertProfileDlg::setTableMenus()
{
    QStringList sPolicyLabels = { tr("OID"), tr("CPS"), tr("UserNotice") };
    mPolicyTable->setColumnCount(3);
    mPolicyTable->horizontalHeader()->setStretchLastSection(true);
    mPolicyTable->setHorizontalHeaderLabels( sPolicyLabels );
    mPolicyTable->verticalHeader()->setVisible(false);
    mPolicyTable->horizontalHeader()->setStyleSheet( kTableStyle );
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
    mCRLDPTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLDPTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCRLDPTable->setColumnWidth(0,60);


    QStringList sAIALabels = { tr("Target"), tr("Type"), tr("Value") };
    mAIATable->setColumnCount(3);
    mAIATable->horizontalHeader()->setStretchLastSection(true);
    mAIATable->setHorizontalHeaderLabels(sAIALabels);
    mAIATable->verticalHeader()->setVisible(false);
    mAIATable->horizontalHeader()->setStyleSheet( kTableStyle );
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
    mSANTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mSANTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mSANTable->setColumnWidth(0,60);


    QStringList sIANLabels = { tr("Type"), tr("Value") };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);
    mIANTable->verticalHeader()->setVisible(false);
    mIANTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mIANTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIANTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mIANTable->setColumnWidth(0,60);


    QStringList sPMLabels = { tr("Target"), tr("Value"), tr("Target"), tr("Value") };
    mPMTable->setColumnCount(4);
    mPMTable->horizontalHeader()->setStretchLastSection(true);
    mPMTable->setHorizontalHeaderLabels(sPMLabels);
    mPMTable->verticalHeader()->setVisible(false);
    mPMTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mPMTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mPMTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mPMTable->setColumnWidth(0,100);
    mPMTable->setColumnWidth(1,100);
    mPMTable->setColumnWidth(2,100);


    QStringList sNCLabels = { tr("Type"), tr("Target"), tr("Value"), tr("Min"), tr("Max") };
    mNCTable->setColumnCount(5);
    mNCTable->horizontalHeader()->setStretchLastSection(true);
    mNCTable->setHorizontalHeaderLabels(sNCLabels);
    mNCTable->verticalHeader()->setVisible(false);
    mNCTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mNCTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mNCTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mNCTable->setColumnWidth(0,60);
    mNCTable->setColumnWidth(1,120);
    mNCTable->setColumnWidth(2,200);
    mNCTable->setColumnWidth(3,60);
    mNCTable->setColumnWidth(4,60);
}

void MakeCertProfileDlg::connectExtends()
{
    connect( mUseCSRCheck, SIGNAL(clicked()), this, SLOT(clickUseCSR()));
    connect( mUseDaysCheck, SIGNAL(clicked()), this, SLOT(clickUseDays()));

    connect( mAIAUseCheck, SIGNAL(clicked()), this, SLOT(clickAIAUse()));
    connect( mAKIUseCheck, SIGNAL(clicked()), this, SLOT(clickAKIUse()));
    connect( mBCUseCheck, SIGNAL(clicked()), this, SLOT(clickBCUse()));
    connect( mCRLDPUseCheck, SIGNAL(clicked()), this, SLOT(clickCRLDPUse()));
    connect( mEKUUseCheck, SIGNAL(clicked()), this, SLOT(clickEKUUse()));
    connect( mIANUseCheck, SIGNAL(clicked()), this, SLOT(clickIANUse()));
    connect( mKeyUsageUseCheck, SIGNAL(clicked()), this, SLOT(clickKeyUsageUse()));
    connect( mNCUseCheck, SIGNAL(clicked()), this, SLOT( clickNCUse()));
    connect( mPolicyUseCheck, SIGNAL(clicked()), this, SLOT(clickPolicyUse()));
    connect( mPCUseCheck, SIGNAL(clicked()), this, SLOT(clickPCUse()));
    connect( mPMUseCheck, SIGNAL(clicked()), this, SLOT(clickPMUse()));
    connect( mSKIUseCheck, SIGNAL(clicked()), this, SLOT(clickSKIUse()));
    connect( mSANUseCheck, SIGNAL(clicked()), this, SLOT(clickSANUse()));

    connect( mKeyUsageAddBtn, SIGNAL(clicked()), this, SLOT(addKeyUsage()));
    connect( mPolicyAddBtn, SIGNAL(clicked()), this, SLOT(addPolicy()));
    connect( mEKUAddBtn, SIGNAL(clicked()), this, SLOT(addEKU()));
    connect( mCRLDPAddBtn, SIGNAL(clicked()), this, SLOT(addCRLDP()));
    connect( mAIAAddBtn, SIGNAL(clicked()), this, SLOT(addAIA()));
    connect( mSANAddBtn, SIGNAL(clicked()), this, SLOT(addSAN()));
    connect( mIANAddBtn, SIGNAL(clicked()), this, SLOT(addIAN()));
    connect( mPMAddBtn, SIGNAL(clicked()), this, SLOT(addPM()));
    connect( mNCAddBtn, SIGNAL(clicked()), this, SLOT(addNC()));

    connect( mKeyUsageClearBtn, SIGNAL(clicked()), this, SLOT(clearKeyUsage()));
    connect( mPolicyClearBtn, SIGNAL(clicked()), this, SLOT(clearPolicy()));
    connect( mEKUClearBtn, SIGNAL(clicked()), this, SLOT(clearEKU()));
    connect( mCRLDPClearBtn, SIGNAL(clicked()), this, SLOT(clearCRLDP()));
    connect( mAIAClearBtn, SIGNAL(clicked()), this, SLOT(clearAIA()));
    connect( mSANClearBtn, SIGNAL(clicked()), this, SLOT(clearSAN()));
    connect( mIANClearBtn, SIGNAL(clicked()), this, SLOT(clearIAN()));
    connect( mPMClearBtn, SIGNAL(clicked()), this, SLOT(clearPM()));
    connect( mNCClearBtn, SIGNAL(clicked()), this, SLOT(clearNC()));

    connect( mKeyUsageList, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotKeyUsageMenuRequested(QPoint)));
    connect( mEKUList, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotEKUMenuRequested(QPoint)));
    connect( mPolicyTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotPolicyMenuRequested(QPoint)));
    connect( mCRLDPTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotCRLDPMenuRequested(QPoint)));
    connect( mAIATable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotAIAMenuRequested(QPoint)));
    connect( mSANTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotSANMenuRequested(QPoint)));
    connect( mIANTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotIANMenuRequested(QPoint)));
    connect( mPMTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotPMMenuRequested(QPoint)));
    connect( mNCTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotNCMenuRequested(QPoint)));
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

void MakeCertProfileDlg::deleteNCMenu()
{
    QModelIndex idx = mNCTable->currentIndex();
    mNCTable->removeRow( idx.row() );
}

void MakeCertProfileDlg::clickUseCSR()
{
    bool bStatus = mUseCSRCheck->isChecked();

    mSubjectDNText->setEnabled( !bStatus );

    if( bStatus )
        mSubjectDNText->setText( "#CSR" );
    else {
        mSubjectDNText->setText( "" );
    }
}

void MakeCertProfileDlg::clickUseDays()
{
    bool bStatus = mUseDaysCheck->isChecked();

    mDaysText->setEnabled(bStatus);
    mNotAfterDateTime->setEnabled(!bStatus);
    mNotBeforeDateTime->setEnabled(!bStatus);
}

void MakeCertProfileDlg::setExtends()
{
    clickUseCSR();
    clickUseDays();

    clickAIAUse();
    clickAKIUse();
    clickBCUse();
    clickCRLDPUse();
    clickEKUUse();
    clickIANUse();
    clickKeyUsageUse();
    clickNCUse();
    clickPolicyUse();
    clickPCUse();
    clickPMUse();
    clickSKIUse();
    clickSANUse();
}


void MakeCertProfileDlg::clickAIAUse()
{
    bool bStatus = mAIAUseCheck->isChecked();

    mAIACriticalCheck->setEnabled(bStatus);
    mAIAClearBtn->setEnabled(bStatus);
    mAIAAddBtn->setEnabled(bStatus);
    mAIATypeCombo->setEnabled(bStatus);
    mAIATargetCombo->setEnabled(bStatus);
    mAIAText->setEnabled(bStatus);
    mAIATable->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickAKIUse()
{
    bool bStatus = mAKIUseCheck->isChecked();

    mAKICriticalCheck->setEnabled(bStatus);
    mAKICertIssuerCheck->setEnabled(bStatus);
    mAKICertSerialCheck->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickBCUse()
{
    bool bStatus = mBCUseCheck->isChecked();

    mBCCriticalCheck->setEnabled(bStatus);
    mBCCombo->setEnabled(bStatus);
    mBCPathLenText->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickCRLDPUse()
{
    bool bStatus = mCRLDPUseCheck->isChecked();

    mCRLDPCriticalCheck->setEnabled( bStatus );
    mCRLDPCombo->setEnabled(bStatus);
    mCRLDPClearBtn->setEnabled(bStatus);
    mCRLDPAddBtn->setEnabled(bStatus);
    mCRLDPText->setEnabled(bStatus);
    mCRLDPTable->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickEKUUse()
{
    bool bStatus = mEKUUseCheck->isChecked();

    mEKUCriticalCheck->setEnabled( bStatus );
    mEKUCombo->setEnabled(bStatus);
    mEKUClearBtn->setEnabled(bStatus);
    mEKUAddBtn->setEnabled(bStatus);
    mEKUList->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickIANUse()
{
    bool bStatus = mIANUseCheck->isChecked();

    mIANCriticalCheck->setEnabled(bStatus);
    mIANCombo->setEnabled(bStatus);
    mIANText->setEnabled(bStatus);
    mIANTable->setEnabled(bStatus);
    mIANClearBtn->setEnabled(bStatus);
    mIANAddBtn->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickKeyUsageUse()
{
    bool bStatus = mKeyUsageUseCheck->isChecked();

    mKeyUsageCriticalCheck->setEnabled( bStatus );
    mKeyUsageCombo->setEnabled( bStatus );
    mKeyUsageClearBtn->setEnabled( bStatus );
    mKeyUsageAddBtn->setEnabled( bStatus );
    mKeyUsageList->setEnabled( bStatus );
}

void MakeCertProfileDlg::clickNCUse()
{
    bool bStatus = mNCUseCheck->isChecked();

    mNCCriticalCheck->setEnabled(bStatus);
    mNCSubCombo->setEnabled(bStatus);
    mNCClearBtn->setEnabled(bStatus);
    mNCAddBtn->setEnabled(bStatus);
    mNCTypeCombo->setEnabled(bStatus);
    mNCSubText->setEnabled(bStatus);
    mNCMaxText->setEnabled(bStatus);
    mNCMinText->setEnabled(bStatus);
    mNCTable->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickPolicyUse()
{
    bool bStatus = mPolicyUseCheck->isChecked();

    mPolicyCriticalCheck->setEnabled( bStatus );
    mPolicyClearBtn->setEnabled( bStatus );
    mPolicyAddBtn->setEnabled( bStatus );
    mPolicyOIDText->setEnabled( bStatus );
    mPolicyCPSText->setEnabled( bStatus );
    mPolicyUserNoticeText->setEnabled( bStatus );
    mPolicyTable->setEnabled( bStatus );
}

void MakeCertProfileDlg::clickPCUse()
{
    bool bStatus = mPCUseCheck->isChecked();

    mPCCriticalCheck->setEnabled(bStatus);
    mPCInhibitText->setEnabled(bStatus);
    mPCExplicitText->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickPMUse()
{
    bool bStatus = mPMUseCheck->isChecked();

    mPMCriticalCheck->setEnabled(bStatus);
    mPMClearBtn->setEnabled( bStatus );
    mPMAddBtn->setEnabled(bStatus);
    mPMIssuerDomainPolicyText->setEnabled(bStatus);
    mPMSubjectDomainPolicyText->setEnabled(bStatus);
    mPMTable->setEnabled(bStatus);
}

void MakeCertProfileDlg::clickSKIUse()
{
    bool bStatus = mSKIUseCheck->isChecked();

    mSKICriticalCheck->setEnabled( bStatus );
}

void MakeCertProfileDlg::clickSANUse()
{
    bool bStatus = mSANUseCheck->isChecked();

    mSANCriticalCheck->setEnabled(bStatus);
    mSANCombo->setEnabled(bStatus);
    mSANClearBtn->setEnabled( bStatus );
    mSANAddBtn->setEnabled(bStatus);
    mSANText->setEnabled(bStatus);
    mSANTable->setEnabled(bStatus);
}


void MakeCertProfileDlg::addKeyUsage()
{
    QString strVal = mKeyUsageCombo->currentText();

    mKeyUsageList->addItem( strVal );
}

void MakeCertProfileDlg::addPolicy()
{
    QString strOID = mPolicyOIDText->text();
    QString strCPS = mPolicyCPSText->text();
    QString strUserNotice = mPolicyUserNoticeText->text();

    int row = mPolicyTable->rowCount();

    mPolicyTable->setRowCount( row + 1 );

    mPolicyTable->setRowHeight( row, 10 );
    mPolicyTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mPolicyTable->setItem( row, 1, new QTableWidgetItem(strCPS));
    mPolicyTable->setItem( row, 2, new QTableWidgetItem(strUserNotice));
}

void MakeCertProfileDlg::addEKU()
{
    QString strVal = mEKUCombo->currentText();

    mEKUList->addItem( strVal );
}

void MakeCertProfileDlg::addCRLDP()
{
    QString strType = mCRLDPCombo->currentText();
    QString strVal = mCRLDPText->text();

    int row = mCRLDPTable->rowCount();
    mCRLDPTable->setRowCount( row + 1 );

    mCRLDPTable->setRowHeight( row, 10 );
    mCRLDPTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mCRLDPTable->setItem( row, 1, new QTableWidgetItem( strVal ));
}

void MakeCertProfileDlg::addAIA()
{
    QString strTarget = mAIATargetCombo->currentText();
    QString strType = mAIATypeCombo->currentText();
    QString strVal = mAIAText->text();

    int row = mAIATable->rowCount();

    mAIATable->setRowCount( row + 1 );

    mAIATable->setRowHeight( row, 10 );
    mAIATable->setItem( row, 0, new QTableWidgetItem( strTarget ));
    mAIATable->setItem( row, 1, new QTableWidgetItem( strType) );
    mAIATable->setItem( row, 2, new QTableWidgetItem( strVal ));
}

void MakeCertProfileDlg::addSAN()
{
    QString strType = mSANCombo->currentText();
    QString strVal = mSANText->text();

    int row = mSANTable->rowCount();
    mSANTable->setRowCount( row + 1 );

    mSANTable->setRowHeight( row, 10 );
    mSANTable->setItem( row, 0, new QTableWidgetItem(strType));
    mSANTable->setItem( row, 1, new QTableWidgetItem(strVal));
}

void MakeCertProfileDlg::addIAN()
{
    QString strType = mIANCombo->currentText();
    QString strVal = mIANText->text();

    int row = mIANTable->rowCount();
    mIANTable->setRowCount( row + 1 );

    mIANTable->setRowHeight( row, 10 );
    mIANTable->setItem( row, 0, new QTableWidgetItem(strType));
    mIANTable->setItem( row, 1, new QTableWidgetItem(strVal));
}

void MakeCertProfileDlg::addPM()
{
    QString strIDP = mPMIssuerDomainPolicyText->text();
    QString strSDP = mPMSubjectDomainPolicyText->text();

    int row = mPMTable->rowCount();
    mPMTable->setRowCount( row + 1 );

    mPMTable->setRowHeight( row, 10 );
    mPMTable->setItem( row, 0, new QTableWidgetItem( "IssuerDomainPolicy"));
    mPMTable->setItem( row, 1, new QTableWidgetItem( strIDP));
    mPMTable->setItem( row, 2, new QTableWidgetItem( "SubjectDomainPolicy"));
    mPMTable->setItem( row, 3, new QTableWidgetItem( strSDP));
}

void MakeCertProfileDlg::addNC()
{
    QString strType = mNCTypeCombo->currentText();
    QString strSubType = mNCSubCombo->currentText();
    QString strVal = mNCSubText->text();
    QString strMax = mNCMaxText->text();
    QString strMin = mNCMinText->text();

    int row = mNCTable->rowCount();
    mNCTable->setRowCount( row + 1 );

    mNCTable->setRowHeight( row, 10 );
    mNCTable->setItem( row, 0, new QTableWidgetItem(strType));
    mNCTable->setItem( row, 1, new QTableWidgetItem(strSubType));
    mNCTable->setItem( row, 2, new QTableWidgetItem(strVal));
    mNCTable->setItem( row, 3, new QTableWidgetItem(strMax));
    mNCTable->setItem( row, 4, new QTableWidgetItem(strMin));
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

void MakeCertProfileDlg::saveAIAUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "authorityInfoAccess" );
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

        if( i != 0 ) strVal += "#";
        strVal += strMethod;
        strVal += "$";
        strVal += strType;
        strVal += "$";
        strVal += strData;
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension(profileExt);
}

void MakeCertProfileDlg::saveAKIUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "authorityKeyIdentifier" );
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

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN("basicConstraints");
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
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "crlDistributionPoints");
    profileExt.setCritical( mCRLDPCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mCRLDPTable->rowCount(); i++ )
    {
        QString strType = "";
        QString strData = "";

        strType = mCRLDPTable->takeItem( i, 0 )->text();
        strData = mCRLDPTable->takeItem( i, 1 )->text();

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveEKUUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "extendedKeyUsage");
    profileExt.setCritical( mEKUCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mEKUList->count(); i++ )
    {
        if( i != 0 ) strVal += "#";
        strVal += mEKUList->item(i)->text();
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveIANUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "issuerAltName" );
    profileExt.setCritical( mIANCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; i < mIANTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mIANTable->takeItem( i, 0)->text();
        strData = mIANTable->takeItem( i, 1)->text();

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveKeyUsageUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "keyUsage");
    profileExt.setCritical( mKeyUsageCriticalCheck->isChecked() );

    QString strValue;

    for( int i =0; i < mKeyUsageList->count(); i++ )
    {
        if( i != 0 ) strValue += "#";
        strValue += mKeyUsageList->item(i)->text();
    }

    profileExt.setValue( strValue );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveNCUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "nameConstraints" );
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
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::savePolicyUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "certificatePolicies" );
    profileExt.setCritical( mPolicyCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; i < mPolicyTable->rowCount(); i++ )
    {
        if( i != 0 ) strVal += "%%";

        strVal += "OID$";
        strVal += mPolicyTable->takeItem(i,0)->text();
        strVal += "#CPS$";
        strVal += mPolicyTable->takeItem(i,1)->text();
        strVal += "#UserNotice$";
        strVal += mPolicyTable->takeItem(i,2)->text();
        strVal += "#";
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::savePCUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "policyConstraints" );
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
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "policyMappings" );
    profileExt.setCritical( mPMCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; i < mPMTable->rowCount(); i++ )
    {
        QString strIDP;
        QString strSDP;

        strIDP = mPMTable->takeItem(i, 1)->text();
        strSDP = mPMTable->takeItem(i, 3)->text();

        if( i != 0 ) strVal += "#";
        strVal += strIDP;
        strVal += "$";
        strVal += strSDP;
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::saveSKIUse(int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "subjectKeyIdentifier" );
    profileExt.setCritical( mSKICriticalCheck->isChecked() );

    dbMgr->addCertProfileExtension(profileExt);
}

void MakeCertProfileDlg::saveSANUse(int nProfileNum)
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "subjectAltName" );
    profileExt.setCritical( mSANCriticalCheck->isChecked() );

    QString strVal = "";
    for( int i=0; i < mSANTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mSANTable->takeItem( i, 0 )->text();
        strData = mSANTable->takeItem( i, 1 )->text();

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;
    }

    profileExt.setValue( strVal );
    dbMgr->addCertProfileExtension( profileExt );
}

void MakeCertProfileDlg::setAIAUse( ProfileExtRec& profileRec )
{
    mAIAUseCheck->setChecked(true);
    mAIACriticalCheck->setChecked(profileRec.isCritical());
    clickAIAUse();

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QString strMethod = "";
        QString strType = "";
        QString strData = "";

        QStringList infoList = info.split("$");
        strMethod = infoList.at(0);
        strType = infoList.at(1);
        strData = infoList.at(2);

        mAIATable->insertRow(i);
        mAIATable->setRowHeight(i,10);
        mAIATable->setItem( i, 0, new QTableWidgetItem(strMethod));
        mAIATable->setItem( i, 1, new QTableWidgetItem(strType));
        mAIATable->setItem( i, 2, new QTableWidgetItem(strData));
    }
}

void MakeCertProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    mAKIUseCheck->setChecked(true);
    mAKICriticalCheck->setChecked( profileRec.isCritical() );
    clickAKIUse();

    QString strVal = profileRec.getValue();

    bool bStatus = strVal.contains("ISSUER");
    mAKICertIssuerCheck->setChecked(bStatus);

    bStatus = strVal.contains("SERIAL");
    mAKICertSerialCheck->setChecked(bStatus);
}

void MakeCertProfileDlg::setBCUse( ProfileExtRec& profileRec )
{
    mBCUseCheck->setChecked(true);
    mBCCriticalCheck->setChecked(profileRec.isCritical());
    clickBCUse();

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");
    QString strType= valList.at(0);
    QString strLen = valList.at(1);

    mBCCombo->setCurrentText( strType );
    mBCPathLenText->setText( strLen );
}

void MakeCertProfileDlg::setCRLDPUse( ProfileExtRec& profileRec )
{
    mCRLDPUseCheck->setChecked(true);
    mCRLDPCriticalCheck->setChecked(profileRec.isCritical());
    clickCRLDPUse();

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
    }
}

void MakeCertProfileDlg::setEKUUse( ProfileExtRec& profileRec )
{
    QString strVal = "";

    mEKUUseCheck->setChecked(true);
    mEKUCriticalCheck->setChecked(profileRec.isCritical());
    clickEKUUse();

    strVal = profileRec.getValue();
    QStringList valList = strVal.split("#");

    if( valList.size() > 0 ) mEKUList->insertItems( 0, valList );
}

void MakeCertProfileDlg::setIANUse( ProfileExtRec& profileRec )
{
    mIANUseCheck->setChecked(true);
    mIANCriticalCheck->setChecked(profileRec.isCritical());
    clickIANUse();

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mIANTable->insertRow(i);
        mIANTable->setRowHeight( i, 10 );
        mIANTable->setItem( i, 0, new QTableWidgetItem(strType));
        mIANTable->setItem(i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCertProfileDlg::setKeyUsageUse( ProfileExtRec& profileRec )
{
    mKeyUsageUseCheck->setChecked(true);
    mKeyUsageCriticalCheck->setChecked( profileRec.isCritical() );
    clickKeyUsageUse();

    QString strVal = profileRec.getValue();

    mKeyUsageList->clear();

    QStringList valList = strVal.split("#");
    if( valList.size() > 0 ) mKeyUsageList->insertItems(0, valList );
}

void MakeCertProfileDlg::setNCUse( ProfileExtRec& profileRec )
{
    mNCUseCheck->setChecked(true);
    mNCCriticalCheck->setChecked(profileRec.isCritical());
    clickNCUse();

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
    mPolicyUseCheck->setChecked(true);
    mPolicyCriticalCheck->setChecked(profileRec.isCritical());
    clickPolicyUse();

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
    }
}

void MakeCertProfileDlg::setPCUse( ProfileExtRec& profileRec )
{
    mPCUseCheck->setChecked(true);
    mPCCriticalCheck->setChecked(profileRec.isCritical());
    clickPCUse();

    QString strVal = profileRec.getValue();
    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

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
    mPMUseCheck->setChecked(true);
    mPMCriticalCheck->setChecked(profileRec.isCritical());
    clickPMUse();

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

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
    mSKIUseCheck->setChecked(true);
    mSKICriticalCheck->setChecked(profileRec.isCritical());
    clickSKIUse();
}

void MakeCertProfileDlg::setSANUse( ProfileExtRec& profileRec )
{
    mSANUseCheck->setChecked(true);
    mSANCriticalCheck->setChecked(profileRec.isCritical());
    clickSANUse();

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
    }
}
