/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>
#include "js_gen.h"
#include "js_pki_ext.h"
#include "make_crl_profile_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "profile_ext_rec.h"
#include "crl_profile_rec.h"
#include "db_mgr.h"
#include "commons.h"

static QStringList sTypeList = { "URI", "email", "DNS" };
static QStringList sVersionList = { "V1", "V2" };

static QStringList kPeriodTypes = { "Day", "Month", "Year" };


MakeCRLProfileDlg::MakeCRLProfileDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    connectExtends();
    setTableMenus();

    is_edit_ = false;
    profile_num_ = -1;

    connect( mValidDaysTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValidDaysType(int)));
    connect( mCRLNumAutoCheck, SIGNAL(clicked()), this, SLOT(clickCRLNumAuto()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();

    mCloseBtn->setDefault(true);
    mNameText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mBaseTab->layout()->setSpacing(5);
    mBaseTab->layout()->setMargin(5);

    mExtendTab->layout()->setSpacing(5);
    mExtendTab->layout()->setMargin(5);

    mExtensionsGroup->layout()->setSpacing(5);
    mExtensionsGroup->layout()->setMargin(5);

    mCRLNumGroup->layout()->setSpacing(5);
    mCRLNumGroup->layout()->setMargin(5);

    mAKIGroup->layout()->setSpacing(5);
    mAKIGroup->layout()->setMargin(5);

    mIDPGroup->layout()->setSpacing(5);
    mIDPGroup->layout()->setMargin(5);

    mIANGroup->layout()->setSpacing(5);
    mIANGroup->layout()->setMargin(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeCRLProfileDlg::~MakeCRLProfileDlg()
{

}

void MakeCRLProfileDlg::setEdit( int nProfileNum)
{
    is_edit_ = true;
    profile_num_ = nProfileNum;
    setWindowTitle( tr( "Edit CRL profile" ));
    loadProfile( profile_num_ );
}

void MakeCRLProfileDlg::setReadOnly()
{
    setWindowTitle( tr( "View CRL profile" ));
    mOKBtn->hide();
}

void MakeCRLProfileDlg::initialize()
{
    mCRLTab->setCurrentIndex(0);
    mValidDaysTypeCombo->addItems( kPeriodTypes );
    clickCRLNumAuto();

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

    if( isEdit() )
    {
        DBMgr* dbMgr = manApplet->dbMgr();
        if( dbMgr == NULL ) return;
        QString strSN = mExtensionsTable->item( idx.row(), 0 )->text();
        ext_rmlist_.append( strSN );
    }

    mExtensionsTable->removeRow( idx.row() );
}

void MakeCRLProfileDlg::loadProfile( int nProfileNum, bool bCopy )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CRLProfileRec crlProfile;

    dbMgr->getCRLProfileRec( nProfileNum, crlProfile );

    if( bCopy == true )
        mNameText->setText( crlProfile.getName() + "_Copy" );
    else
        mNameText->setText( crlProfile.getName() );

    mVersionCombo->setCurrentIndex( crlProfile.getVersion() );
    mHashCombo->setCurrentText( crlProfile.getHash() );

    if( crlProfile.getThisUpdate() >= 0 && crlProfile.getThisUpdate() <= 2)
    {
        mUseFromNowCheck->setChecked(true);
        mValidDaysTypeCombo->setCurrentIndex( crlProfile.getThisUpdate() );
        mValidDaysText->setText( QString("%1").arg(crlProfile.getNextUpdate()));
    }
    else
    {
        QDateTime thisUpdate;
        QDateTime nextUpdate;

        mUseFromNowCheck->setChecked(false);

        thisUpdate.setSecsSinceEpoch( crlProfile.getThisUpdate() );
        nextUpdate.setSecsSinceEpoch( crlProfile.getNextUpdate() );

        mThisUpdateDateTime->setDateTime(thisUpdate);
        mNextUpdateDateTime->setDateTime(nextUpdate );
    }

    clickUseFromNow();

    QList<ProfileExtRec> extProfileList;
    dbMgr->getCRLProfileExtensionList( nProfileNum, extProfileList );

    for( int i=0; i < extProfileList.size(); i++ )
    {
        ProfileExtRec extProfile = extProfileList.at(i);

        if( extProfile.getSN() == JS_PKI_ExtNameCRLNum )
            setCRLNumUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameAKI )
            setAKIUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameIDP )
            setIDPUse( extProfile );
        else if( extProfile.getSN() == JS_PKI_ExtNameIAN )
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
    mCRLNumAutoCheck->setChecked(true);
    mCRLNumCriticalCheck->setChecked(false);
    mCRLNumLabel->setEnabled(false);
    mCRLNumText->setEnabled(false);

    mAKICriticalCheck->setChecked(false);
    mAKICertIssuerCheck->setChecked(false);
    mAKICertSerialCheck->setChecked(false);

    rowCnt = mIDPTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mIDPTable->removeRow(0);
    mIDPCriticalCheck->setChecked(false);

    rowCnt = mIANTable->rowCount();
    for( int i=0; i < rowCnt; i++ )
        mIANTable->removeRow(0);

    mIANCriticalCheck->setChecked(false);
    mIANText->setText("");

    mVersionCombo->setCurrentIndex(1);
    mHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

    mUseFromNowCheck->setChecked(true);
    clickUseFromNow();

    mValidDaysText->setText( "10" );
}

void MakeCRLProfileDlg::clickOK()
{
    int ret = 0;
    CRLProfileRec crlProfileRec;
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr( "Enter a name"), this );
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
        crlProfileRec.setThisUpdate( mValidDaysTypeCombo->currentIndex() );
        crlProfileRec.setNextUpdate(mValidDaysText->text().toLong());
    }
    else {
        if( mThisUpdateDateTime->dateTime().toSecsSinceEpoch() <= 10 )
        {
            manApplet->warningBox( QString( tr("time is too early : %1").arg( mThisUpdateDateTime->dateTime().toSecsSinceEpoch())), this );
            return;
        }
        crlProfileRec.setThisUpdate( mThisUpdateDateTime->dateTime().toSecsSinceEpoch() );
        crlProfileRec.setNextUpdate( mNextUpdateDateTime->dateTime().toSecsSinceEpoch() );
    }

    crlProfileRec.setHash( mHashCombo->currentText() );

    if( is_edit_ )
    {
        ret = dbMgr->modCRLProfileRec( profile_num_, crlProfileRec );
        if( ret != 0 ) goto end;

        dbMgr->delCRLProfileExtensionList( profile_num_ );
        nProfileNum = profile_num_;

        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_MOD_CRL_PROFILE, "" );

    }
    else
    {
        ret = dbMgr->addCRLProfileRec( crlProfileRec );
        if( ret != 0 ) goto end;

        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_ADD_CRL_PROFILE, "" );

    }


    /* need to set extend fields here */

    saveCRLNumUse( nProfileNum );
    saveIDPUse( nProfileNum );
    saveAKIUse( nProfileNum );
    saveIANUse( nProfileNum );
    saveExtensionsUse( nProfileNum );

    /* ....... */
end :
    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightCRLProfileList();
        QDialog::accept();
    }
    else
    {
        manApplet->warningBox( tr( "failed to make CRL profile"), this );
        QDialog::reject();
    }
}

void MakeCRLProfileDlg::changeValidDaysType(int index)
{
    QString strType = mValidDaysTypeCombo->currentText();

    mValidDaysLabel->setText( strType.toLower() + "s" );
}

void MakeCRLProfileDlg::initUI()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    mHashCombo->addItems(kHashList);
    mHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

//    mIDPCombo->addItems(sTypeList);
    mIDPCombo->addItem( "URI" );
    mIANCombo->addItems(sTypeList);
    mVersionCombo->addItems(sVersionList);

    QDateTime   now;
    now.setSecsSinceEpoch( time(NULL) );
    mThisUpdateDateTime->setDateTime( now );
    mNextUpdateDateTime->setDateTime( now );

    mCRLNumText->setPlaceholderText( tr( "Hex value" ) );
    mExtensionsOIDText->setPlaceholderText( QString( "Object Identifier" ) );

    mIDPText->setPlaceholderText( tr( "URI address" ));
}

void MakeCRLProfileDlg::connectExtends()
{
    connect( mUseFromNowCheck, SIGNAL(clicked()), this, SLOT(clickUseFromNow()));

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

void MakeCRLProfileDlg::setTableMenus()
{
    QStringList sDPNLabels = { tr("Type"), tr("Value") };
    mIDPTable->setColumnCount(2);
    mIDPTable->horizontalHeader()->setStretchLastSection(true);
    mIDPTable->setHorizontalHeaderLabels(sDPNLabels);
    mIDPTable->verticalHeader()->setVisible(false);
    mIDPTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mIDPTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mIDPTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIDPTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mIDPTable->setColumnWidth(0, 60);

    QStringList sIANLabels = { tr("Type"), tr("Value") };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);
    mIANTable->verticalHeader()->setVisible(false);
    mIANTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mIANTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mIANTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mIANTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mIANTable->setColumnWidth(0, 60);

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

void MakeCRLProfileDlg::clickCRLNumAuto()
{
    bool bStatus = mCRLNumAutoCheck->isChecked();

    mCRLNumLabel->setEnabled( !bStatus );
    mCRLNumText->setEnabled( !bStatus );
}

void MakeCRLProfileDlg::clickUseFromNow()
{
    bool bStatus = mUseFromNowCheck->isChecked();

    mValidDaysText->setEnabled( bStatus );
    mValidDaysTypeCombo->setEnabled( bStatus );
    mThisUpdateDateTime->setEnabled( !bStatus );
    mNextUpdateDateTime->setEnabled( !bStatus );
}

void MakeCRLProfileDlg::addIDP()
{
    QString strType = mIDPCombo->currentText();
    QString strVal = mIDPText->text();

    if( strVal.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter Issuing Distribution Point value" ), this );
        return;
    }

    int row = mIDPTable->rowCount();
    for( int i = 0; i < row; i++ )
    {
        QTableWidgetItem *item = mIDPTable->item( i, 1 );
        if( item->text() == strVal )
        {
            manApplet->warningBox( tr( "%1 has already been added.").arg( strVal ), this );
            return;
        }
    }

    mIDPTable->setRowCount( row + 1 );

    mIDPTable->setRowHeight( row, 10 );
    mIDPTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mIDPTable->setItem( row, 1, new QTableWidgetItem( strVal ));

    mIDPText->clear();
}

void MakeCRLProfileDlg::addIAN()
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

    mIANTable->setRowCount( row + 1 );

    mIANTable->setRowHeight( row, 10 );
    mIANTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mIANTable->setItem( row, 1, new QTableWidgetItem( strVal ));

    mIANText->clear();
}

void MakeCRLProfileDlg::addExtensions()
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
        strCrit = "true";
    else
        strCrit = "false";

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

    mExtensionsTable->setRowCount( row + 1 );
    mExtensionsTable->setRowHeight( row, 10 );
    mExtensionsTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mExtensionsTable->setItem( row, 1, new QTableWidgetItem(strCrit));
    mExtensionsTable->setItem( row, 2, new QTableWidgetItem(strValue));

    mExtensionsOIDText->clear();
    mExtensionsValueText->clear();
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
    {
        if( isEdit() )
        {
            QString strSN = mExtensionsTable->item( 0, 0 )->text();
            ext_rmlist_.append( strSN );
        }

        mExtensionsTable->removeRow(0);
    }
}

void MakeCRLProfileDlg::saveCRLNumUse( int nProfileNum )
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCRLProfileExtension( profile_num_, JS_PKI_ExtNameCRLNum );
    if( mCRLNumGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameCRLNum );
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

    if( isEdit() ) dbMgr->delCRLProfileExtension( profile_num_, JS_PKI_ExtNameAKI );
    if( mAKIGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameAKI );
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
    int nIDPCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCRLProfileExtension( profile_num_, JS_PKI_ExtNameIDP );
    if( mIDPGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameIDP );
    profileExt.setCritical( mIDPCriticalCheck->isChecked() );

    QString strVal;

    for( int i = 0; i < mIDPTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mIDPTable->takeItem(i,0)->text();
        strData = mIDPTable->takeItem(i,1)->text();

        if( strData.length() < 1 ) continue;

        if( i != 0 ) strVal += "#";
        strVal += strType;
        strVal += "$";
        strVal += strData;

        nIDPCnt++;
    }

    if( nIDPCnt > 0 )
    {
        profileExt.setValue(strVal);
        dbMgr->addCRLProfileExtension(profileExt);
    }
}

void MakeCRLProfileDlg::saveIANUse( int nProfileNum )
{
    int nIANCnt = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( isEdit() ) dbMgr->delCRLProfileExtension( profile_num_, JS_PKI_ExtNameIAN );
    if( mIANGroup->isChecked() == false ) return;

    ProfileExtRec profileExt;

    profileExt.setProfileNum(nProfileNum);
    profileExt.setSN( JS_PKI_ExtNameIAN );
    profileExt.setCritical( mIANCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mIANTable->rowCount(); i++ )
    {
        QString strType;
        QString strData;

        strType = mIANTable->takeItem(i,0)->text();
        strData = mIANTable->takeItem(i,1)->text();

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
        dbMgr->addCRLProfileExtension(profileExt);
    }
}

void MakeCRLProfileDlg::saveExtensionsUse( int nProfileNum )
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

        if( strCrit == "true" ) bCrit = true;

        ProfileExtRec profileRec;
        profileRec.setProfileNum( nProfileNum );
        profileRec.setSN( strOID );
        profileRec.setValue( strValue );
        profileRec.setCritical( bCrit );

        if( isEdit() ) dbMgr->delCRLProfileExtension( profile_num_, profileRec.getSN() );
        dbMgr->addCRLProfileExtension( profileRec );
    }
}

void MakeCRLProfileDlg::setCRLNumUse( ProfileExtRec& profileRec )
{
    mCRLNumGroup->setChecked(true);
    mCRLNumCriticalCheck->setChecked(profileRec.isCritical());

    QString strVal = profileRec.getValue();

    if( strVal == "auto" )
        mCRLNumAutoCheck->setChecked(true);
    else
        mCRLNumText->setText( strVal );
}

void MakeCRLProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    mAKIGroup->setChecked(true);
    mAKICriticalCheck->setChecked(profileRec.isCritical());

    QString strVal = profileRec.getValue();

    mAKICertIssuerCheck->setChecked( strVal.contains("ISSUER") );
    mAKICertSerialCheck->setChecked( strVal.contains("SERIAL") );
}

void MakeCRLProfileDlg::setIDPUse( ProfileExtRec& profileRec )
{
    mIDPGroup->setChecked(true);
    mIDPCriticalCheck->setChecked(profileRec.isCritical());

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
        mIANTable->setItem( i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCRLProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{
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
