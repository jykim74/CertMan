#include <QMenu>

#include "make_crl_profile_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "profile_ext_rec.h"
#include "crl_profile_rec.h"
#include "db_mgr.h"
#include "commons.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
static QStringList sTypeList = { "URI", "email", "DNS" };
static QStringList sVersionList = { "V1", "V2" };


MakeCRLProfileDlg::MakeCRLProfileDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    connectExtends();
    setExtends();
    setTableMenus();

    is_edit_ = false;
    profile_num_ = -1;

    initialize();
}

MakeCRLProfileDlg::~MakeCRLProfileDlg()
{

}

void MakeCRLProfileDlg::setEdit( int nProfileNum)
{
    is_edit_ = true;
    profile_num_ = nProfileNum;

    loadProfile( profile_num_ );
}


void MakeCRLProfileDlg::initialize()
{
    mCRLTab->setCurrentIndex(0);

    defaultProfile();
}

void MakeCRLProfileDlg::slotIANMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteIANMenu()));

    menu->addAction( delAct );
    menu->popup( mIANTable->viewport()->mapToGlobal(pos));
}

void MakeCRLProfileDlg::slotIDPMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteIDPMenu()));

    menu->addAction( delAct );
    menu->popup( mIDPTable->viewport()->mapToGlobal(pos));
}

void MakeCRLProfileDlg::deleteIANMenu()
{
    QModelIndex idx = mIANTable->currentIndex();

    mIANTable->removeRow( idx.row() );
}

void MakeCRLProfileDlg::deleteIDPMenu()
{
    QModelIndex idx = mIDPTable->currentIndex();

    mIDPTable->removeRow( idx.row() );
}

void MakeCRLProfileDlg::slotExtensionsMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteExtensionsMenu()));

    menu->addAction( delAct );
    menu->popup( mExtensionsTable->viewport()->mapToGlobal(pos));
}

void MakeCRLProfileDlg::deleteExtensionsMenu()
{
    QModelIndex idx = mExtensionsTable->currentIndex();
    mExtensionsTable->removeRow( idx.row() );
}

void MakeCRLProfileDlg::loadProfile( int nProfileNum, bool bCopy )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CRLProfileRec crlProfile;

//    dbMgr->getCRLProfileRec( profile_num_, crlProfile );
    dbMgr->getCRLProfileRec( nProfileNum, crlProfile );

    if( bCopy == true )
        mNameText->setText( crlProfile.getName() + "_Copy" );
    else
        mNameText->setText( crlProfile.getName() );

    mVersionCombo->setCurrentIndex( crlProfile.getVersion() );
    mHashCombo->setCurrentText( crlProfile.getHash() );

    if( crlProfile.getLastUpdate() == 0 )
    {
        mUseFromNowCheck->setChecked(true);
        mValidDaysText->setText( QString("%1").arg(crlProfile.getNextUpdate()));
    }
    else
    {
        QDateTime lastUpdate;
        QDateTime nextUpdate;

        lastUpdate.setTime_t( crlProfile.getLastUpdate() );
        nextUpdate.setTime_t( crlProfile.getNextUpdate() );

        mLastUpdateDateTime->setDateTime(lastUpdate);
        mNextUpdateDateTime->setDateTime(nextUpdate );
    }

    clickUseFromNow();

    QList<ProfileExtRec> extProfileList;
    dbMgr->getCRLProfileExtensionList( nProfileNum, extProfileList );

    for( int i=0; i < extProfileList.size(); i++ )
    {
        ProfileExtRec extProfile = extProfileList.at(i);

        if( extProfile.getSN() == kExtNameCRLNum )
            setCRLNumUse( extProfile );
        else if( extProfile.getSN() == kExtNameAKI )
            setAKIUse( extProfile );
        else if( extProfile.getSN() == kExtNameIDP )
            setIDPUse( extProfile );
        else if( extProfile.getSN() == kExtNameIAN )
            setIANUse( extProfile );
        else
            setExtensionsUse( extProfile );
    }
}

void MakeCRLProfileDlg::defaultProfile()
{
    int rowCnt = 0;
    mNameText->setText("");

    mCRLNumText->setText("");
    mCRLNumUseCheck->setChecked(false);
    mCRLNumAutoCheck->setChecked(false);
    mCRLNumCriticalCheck->setChecked(false);

    mAKIUseCheck->setChecked(false);
    mAKICriticalCheck->setChecked(false);
    mAKICertIssuerCheck->setChecked(false);
    mAKICertSerialCheck->setChecked(false);

    rowCnt = mIDPTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mIDPTable->removeRow(0);
    mIDPUseCheck->setChecked(false);
    mIDPCriticalCheck->setChecked(false);

    rowCnt = mIANTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mIANTable->removeRow(0);
    mIANUseCheck->setChecked(false);
    mIANCriticalCheck->setChecked(false);
    mIANText->setText("");

    mVersionCombo->setCurrentIndex(1);
    mHashCombo->setCurrentIndex(2);

    mUseFromNowCheck->setChecked(true);
    clickUseFromNow();

    mValidDaysText->setText( "10" );
}

void MakeCRLProfileDlg::accept()
{
    CRLProfileRec crlProfileRec;
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to insert name"), this );
        mNameText->setFocus();
        return;
    }


    int nProfileNum = dbMgr->getCRLProfileNextNum();
    if( nProfileNum <= 0 ) nProfileNum = 1;

    crlProfileRec.setNum( nProfileNum );
    crlProfileRec.setVersion( mVersionCombo->currentIndex() );
    crlProfileRec.setName( strName );

    if( mUseFromNowCheck->isChecked() )
    {
        crlProfileRec.setLastUpdate(0);
        crlProfileRec.setNextUpdate(mValidDaysText->text().toLong());
    }
    else {
        QDateTime lastTime;
        QDateTime nextTime;

        lastTime.setDate( mLastUpdateDateTime->date() );
        nextTime.setDate( mNextUpdateDateTime->date() );

        crlProfileRec.setLastUpdate( lastTime.toTime_t() );
        crlProfileRec.setNextUpdate( nextTime.toTime_t() );
    }

    crlProfileRec.setHash( mHashCombo->currentText() );

    if( is_edit_ )
    {
        dbMgr->modCRLProfileRec( profile_num_, crlProfileRec );
        dbMgr->delCRLProfileExtensionList( profile_num_ );
        nProfileNum = profile_num_;
    }
    else
    {
        dbMgr->addCRLProfileRec( crlProfileRec );
    }


    /* need to set extend fields here */

    if( mCRLNumUseCheck->isChecked() ) saveCRLNumUse( nProfileNum );
    if( mIDPUseCheck->isChecked() ) saveIDPUse( nProfileNum );
    if( mAKIUseCheck->isChecked() ) saveAKIUse( nProfileNum );
    if( mIANUseCheck->isChecked() ) saveIANUse( nProfileNum );
    if( mExtensionsUseCheck->isChecked() ) saveExtensionsUse( nProfileNum );

    /* ....... */

    manApplet->mainWindow()->createRightCRLProfileList();
    QDialog::accept();
}

void MakeCRLProfileDlg::initUI()
{
    mHashCombo->addItems(sHashList);
//    mIDPCombo->addItems(sTypeList);
    mIDPCombo->addItem( "URI" );
    mIANCombo->addItems(sTypeList);
    mVersionCombo->addItems(sVersionList);

    QDateTime   now;
    now.setTime_t( time(NULL) );
    mLastUpdateDateTime->setDateTime( now );
    mNextUpdateDateTime->setDateTime( now );
}

void MakeCRLProfileDlg::connectExtends()
{
    connect( mUseFromNowCheck, SIGNAL(clicked()), this, SLOT(clickUseFromNow()));
    connect( mCRLNumUseCheck, SIGNAL(clicked()), this, SLOT(clickCRLNum()));
    connect( mAKIUseCheck, SIGNAL(clicked()), this, SLOT(clickAKI()));
    connect( mIDPUseCheck, SIGNAL(clicked()), this, SLOT(clickIDP()));
    connect( mIANUseCheck, SIGNAL(clicked()), this, SLOT(clickIAN()));
    connect( mExtensionsUseCheck, SIGNAL(clicked()), this, SLOT(clickExtensionsUse()));

    connect( mIDPAddBtn, SIGNAL(clicked()), this, SLOT(addIDP()));
    connect( mIANAddBtn, SIGNAL(clicked()), this, SLOT(addIAN()));
    connect( mExtensionsAddBtn, SIGNAL(clicked()), this, SLOT(addExtensions()));

    connect( mIDPClearBtn, SIGNAL(clicked()), this, SLOT(clearIDP()));
    connect( mIANClearBtn, SIGNAL(clicked()), this, SLOT(clearIAN()));
    connect( mExtensionsClearBtn, SIGNAL(clicked()), this, SLOT(clearExtensions()));

    connect( mIANTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotIANMenuRequested(QPoint)));
    connect( mIDPTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotIDPMenuRequested(QPoint)));
    connect( mExtensionsTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotExtensionsMenuRequested(QPoint)));
}

void MakeCRLProfileDlg::setExtends()
{
    clickCRLNum();
    clickAKI();
    clickIDP();
    clickIAN();
    clickExtensionsUse();
}

void MakeCRLProfileDlg::setTableMenus()
{
    QStringList sDPNLabels = { tr("Type"), tr("Value") };
    mIDPTable->setColumnCount(2);
    mIDPTable->horizontalHeader()->setStretchLastSection(true);
    mIDPTable->setHorizontalHeaderLabels(sDPNLabels);
    mIDPTable->verticalHeader()->setVisible(false);
    mIDPTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mIDPTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIDPTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mIDPTable->setColumnWidth(0, 60);

    QStringList sIANLabels = { tr("Type"), tr("Value") };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);
    mIANTable->verticalHeader()->setVisible(false);
    mIANTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mIANTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIANTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mIANTable->setColumnWidth(0, 60);

    QStringList sExtensionsLabels = { tr("OID"), tr("Critical"), tr("Value") };
    mExtensionsTable->setColumnCount(sExtensionsLabels.size());
    mExtensionsTable->horizontalHeader()->setStretchLastSection(true);
    mExtensionsTable->setHorizontalHeaderLabels(sExtensionsLabels);
    mExtensionsTable->verticalHeader()->setVisible(false);
    mExtensionsTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mExtensionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mExtensionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mExtensionsTable->setColumnWidth(0,180);
    mExtensionsTable->setColumnWidth(1,60);
}

void MakeCRLProfileDlg::clickUseFromNow()
{
    bool bStatus = mUseFromNowCheck->isChecked();

    mValidDaysText->setEnabled( bStatus );
    mLastUpdateDateTime->setEnabled( !bStatus );
    mNextUpdateDateTime->setEnabled( !bStatus );
}

void MakeCRLProfileDlg::clickCRLNum()
{
    bool bStatus = mCRLNumUseCheck->isChecked();

    mCRLNumCriticalCheck->setEnabled(bStatus);
    mCRLNumText->setEnabled(bStatus);
    mCRLNumAutoCheck->setEnabled(bStatus);
}

void MakeCRLProfileDlg::clickAKI()
{
    bool bStatus = mAKIUseCheck->isChecked();

    mAKICriticalCheck->setEnabled(bStatus);
    mAKICertIssuerCheck->setEnabled(bStatus);
    mAKICertSerialCheck->setEnabled(bStatus);
}

void MakeCRLProfileDlg::clickIDP()
{
    bool bStatus = mIDPUseCheck->isChecked();

    mIDPCriticalCheck->setEnabled(bStatus);
    mIDPClearBtn->setEnabled(bStatus);
    mIDPAddBtn->setEnabled(bStatus);
    mIDPText->setEnabled(bStatus);
    mIDPTable->setEnabled(bStatus);
    mIDPCombo->setEnabled(bStatus);
}

void MakeCRLProfileDlg::clickIAN()
{
    bool bStatus = mIANUseCheck->isChecked();

    mIANCriticalCheck->setEnabled(bStatus);
    mIANText->setEnabled(bStatus);
    mIANCombo->setEnabled(bStatus);
    mIANTable->setEnabled(bStatus);
    mIANClearBtn->setEnabled(bStatus);
    mIANAddBtn->setEnabled(bStatus);
}

void MakeCRLProfileDlg::clickExtensionsUse()
{
    bool bStatus = mExtensionsUseCheck->isChecked();

    mExtensionsAddBtn->setEnabled(bStatus);
    mExtensionsClearBtn->setEnabled(bStatus);
    mExtensionsOIDText->setEnabled(bStatus);
    mExtensionsCriticalCheck->setEnabled(bStatus);
    mExtensionsValueText->setEnabled(bStatus);
    mExtensionsTable->setEnabled(bStatus);
}

void MakeCRLProfileDlg::addIDP()
{
    QString strType = mIDPCombo->currentText();
    QString strVal = mIDPText->text();

    int row = mIDPTable->rowCount();
    mIDPTable->setRowCount( row + 1 );

    mIDPTable->setRowHeight( row, 10 );
    mIDPTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mIDPTable->setItem( row, 1, new QTableWidgetItem( strVal ));
}

void MakeCRLProfileDlg::addIAN()
{
    QString strType = mIANCombo->currentText();
    QString strVal = mIANText->text();

    int row = mIANTable->rowCount();
    mIANTable->setRowCount( row + 1 );

    mIANTable->setRowHeight( row, 10 );
    mIANTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mIANTable->setItem( row, 1, new QTableWidgetItem( strVal ));
}

void MakeCRLProfileDlg::addExtensions()
{
    QString strOID = mExtensionsOIDText->text();
    QString strValue = mExtensionsValueText->toPlainText();
    bool bCrit = mExtensionsCriticalCheck->isChecked();
    QString strCrit;

    if( bCrit )
        strCrit = "ture";
    else
        strCrit = "false";

    int row = mExtensionsTable->rowCount();
    mExtensionsTable->setRowCount( row + 1 );
    mExtensionsTable->setRowHeight( row, 10 );
    mExtensionsTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mExtensionsTable->setItem( row, 1, new QTableWidgetItem(strCrit));
    mExtensionsTable->setItem( row, 2, new QTableWidgetItem(strValue));
}

void MakeCRLProfileDlg::clearIDP()
{
    int nCnt = mIDPTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mIDPTable->removeRow(0);
}

void MakeCRLProfileDlg::clearIAN()
{
    int nCnt = mIANTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mIANTable->removeRow(0);
}

void MakeCRLProfileDlg::clearExtensions()
{
    int nCount = mExtensionsTable->rowCount();

    for( int i = 0; i < nCount; i++ )
        mExtensionsTable->removeRow(0);
}

void MakeCRLProfileDlg::saveCRLNumUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "crlNumber" );
    profileExt.setCritical( mCRLNumCriticalCheck->isChecked() );

    QString strVal;

    if( mCRLNumAutoCheck->isChecked() )
        strVal = "auto";
    else {
        strVal = mCRLNumText->text();
    }

    profileExt.setValue( strVal );
    dbMgr->addCRLProfileExtension( profileExt );
}

void MakeCRLProfileDlg::saveAKIUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "authorityKeyIdentifier" );
    profileExt.setCritical( mAKICriticalCheck->isChecked() );

    QString strVal;

    if( mAKICertIssuerCheck->isChecked() )
        strVal += "ISSUER#";

    if( mAKICertSerialCheck->isChecked() )
        strVal += "SERIAL#";

    profileExt.setValue( strVal );
    dbMgr->addCRLProfileExtension(profileExt);
}

void MakeCRLProfileDlg::saveIDPUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "issuingDistributionPoint" );
    profileExt.setCritical( mIDPCriticalCheck->isChecked() );

    QString strVal;

    for( int i = 0; i < mIDPTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mIDPTable->takeItem(i,0)->text();
        strData = mIDPTable->takeItem(i,1)->text();

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;
    }

    profileExt.setValue(strVal);
    dbMgr->addCRLProfileExtension(profileExt);
}

void MakeCRLProfileDlg::saveIANUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( "issuerAltName" );
    profileExt.setCritical( mIANCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mIANTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mIANTable->takeItem(i,0)->text();
        strData = mIANTable->takeItem(i,1)->text();

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;
    }

    profileExt.setValue( strVal );
    dbMgr->addCRLProfileExtension(profileExt);
}

void MakeCRLProfileDlg::saveExtensionsUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;
    int nCount = mExtensionsTable->rowCount();

    for( int i = 0; i < nCount; i++ )
    {
        bool bCrit = false;
        QString strOID = mExtensionsTable->takeItem( i, 0 )->text();
        QString strCrit = mExtensionsTable->takeItem( i, 1 )->text();
        QString strValue = mExtensionsTable->takeItem( i, 2)->text();

        if( strCrit == "true" ) bCrit = true;

        ProfileExtRec profileRec;
        profileRec.setProfileNum( nProfileNum );
        profileRec.setSN( strOID );
        profileRec.setValue( strValue );
        profileRec.setCritical( bCrit );

        dbMgr->addCRLProfileExtension( profileRec );
    }
}

void MakeCRLProfileDlg::setCRLNumUse( ProfileExtRec& profileRec )
{
    mCRLNumUseCheck->setChecked(true);
    mCRLNumCriticalCheck->setChecked(profileRec.isCritical());
    clickCRLNum();

    QString strVal = profileRec.getValue();

    if( strVal == "auto" )
        mCRLNumAutoCheck->setChecked(true);
    else
        mCRLNumText->setText( strVal );
}

void MakeCRLProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    mAKIUseCheck->setChecked(true);
    mAKICriticalCheck->setChecked(profileRec.isCritical());
    clickAKI();

    QString strVal = profileRec.getValue();

    mAKICertIssuerCheck->setChecked( strVal.contains("ISSUER") );
    mAKICertSerialCheck->setChecked( strVal.contains("SERIAL") );
}

void MakeCRLProfileDlg::setIDPUse( ProfileExtRec& profileRec )
{
    mIDPUseCheck->setChecked(true);
    mIDPCriticalCheck->setChecked(profileRec.isCritical());
    clickIDP();

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");
    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);

        QStringList infoList = info.split("$");
        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mIDPTable->insertRow(i);
        mIDPTable->setRowHeight( i, 10 );
        mIDPTable->setItem(i, 0, new QTableWidgetItem(strType));
        mIDPTable->setItem(i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCRLProfileDlg::setIANUse( ProfileExtRec& profileRec )
{
    mIANUseCheck->setChecked(true);
    mIANCriticalCheck->setChecked(profileRec.isCritical());
    clickIAN();

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
        mIANTable->setItem( i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCRLProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{
    mExtensionsUseCheck->setChecked(true);
    clickExtensionsUse();

    QString strOID = profileRec.getSN();
    QString strValue = profileRec.getValue();
    QString strCrit;

    if( profileRec.isCritical() )
        strCrit = "true";
    else
        strCrit = "false";

    int row = mExtensionsTable->rowCount();
    mExtensionsTable->setRowCount( row + 1 );
    mExtensionsTable->setRowHeight( row, 10 );
    mExtensionsTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mExtensionsTable->setItem( row, 1, new QTableWidgetItem(strCrit));
    mExtensionsTable->setItem( row, 2, new QTableWidgetItem(strValue));
}
