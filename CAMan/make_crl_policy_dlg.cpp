#include "make_crl_policy_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "policy_ext_rec.h"
#include "crl_policy_rec.h"
#include "db_mgr.h"
#include "commons.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
static QStringList sTypeList = { "URI", "email", "DNS" };
static QStringList sVersionList = { "V1", "V2" };


MakeCRLPolicyDlg::MakeCRLPolicyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    connectExtends();
    setExtends();
    setTableMenus();

    is_edit_ = false;
    policy_num_ = -1;
}

MakeCRLPolicyDlg::~MakeCRLPolicyDlg()
{

}

void MakeCRLPolicyDlg::setEdit(bool is_edit)
{
    is_edit_ = is_edit;
}

void MakeCRLPolicyDlg::setPolicyNum(int policy_num)
{
    policy_num_ = policy_num;
}


void MakeCRLPolicyDlg::initialize()
{
    mCRLTab->setCurrentIndex(0);

    if( is_edit_ )
        loadPolicy();
    else
        defaultPolicy();
}

void MakeCRLPolicyDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void MakeCRLPolicyDlg::loadPolicy()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CRLPolicyRec crlPolicy;

    dbMgr->getCRLPolicyRec( policy_num_, crlPolicy );

    mNameText->setText( crlPolicy.getName() );
    mVersionCombo->setCurrentIndex( crlPolicy.getVersion() );
    mHashCombo->setCurrentText( crlPolicy.getHash() );

    if( crlPolicy.getLastUpdate() == 0 )
    {
        mUseFromNowCheck->setChecked(true);
        mValidDaysText->setText( QString("%1").arg(crlPolicy.getNextUpdate()));
    }
    else
    {
        QDateTime lastUpdate;
        QDateTime nextUpdate;

        lastUpdate.setTime_t( crlPolicy.getLastUpdate() );
        nextUpdate.setTime_t( crlPolicy.getNextUpdate() );

        mLastUpdateDateTime->setDateTime(lastUpdate);
        mNextUpdateDateTime->setDateTime(nextUpdate );
    }

    clickUseFromNow();

    QList<PolicyExtRec> extPolicyList;
    dbMgr->getCRLPolicyExtensionList( policy_num_, extPolicyList );

    for( int i=0; i < extPolicyList.size(); i++ )
    {
        PolicyExtRec extPolicy = extPolicyList.at(i);

        if( extPolicy.getSN() == kExtNameCRLNum )
            setCRLNumUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameAKI )
            setAKIUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameIDP )
            setIDPUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameIAN )
            setIANUse( extPolicy );
    }
}

void MakeCRLPolicyDlg::defaultPolicy()
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

void MakeCRLPolicyDlg::accept()
{
    CRLPolicyRec crlPolicyRec;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();

    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to insert name"), this );
        mNameText->setFocus();
        return;
    }


    int nPolicyNum = dbMgr->getCRLPolicyNextNum();

    crlPolicyRec.setNum( nPolicyNum );
    crlPolicyRec.setVersion( mVersionCombo->currentIndex() );
    crlPolicyRec.setName( strName );

    if( mUseFromNowCheck->isChecked() )
    {
        crlPolicyRec.setLastUpdate(0);
        crlPolicyRec.setNextUpdate(mValidDaysText->text().toLong());
    }
    else {
        QDateTime lastTime;
        QDateTime nextTime;

        lastTime.setDate( mLastUpdateDateTime->date() );
        nextTime.setDate( mNextUpdateDateTime->date() );

        crlPolicyRec.setLastUpdate( lastTime.toTime_t() );
        crlPolicyRec.setNextUpdate( nextTime.toTime_t() );
    }

    crlPolicyRec.setHash( mHashCombo->currentText() );

    if( is_edit_ )
    {
        dbMgr->modCRLPolicyRec( policy_num_, crlPolicyRec );
        dbMgr->delCRLPolicyExtensionList( policy_num_ );
        nPolicyNum = policy_num_;
    }
    else
    {
        dbMgr->addCRLPolicyRec( crlPolicyRec );
    }


    /* need to set extend fields here */

    if( mCRLNumUseCheck->isChecked() ) saveCRLNumUse( nPolicyNum );
    if( mIDPUseCheck->isChecked() ) saveIDPUse( nPolicyNum );
    if( mAKIUseCheck->isChecked() ) saveAKIUse( nPolicyNum );
    if( mIANUseCheck->isChecked() ) saveIANUse( nPolicyNum );

    /* ....... */

    manApplet->mainWindow()->createRightCRLPolicyList();
    QDialog::accept();
}

void MakeCRLPolicyDlg::initUI()
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

void MakeCRLPolicyDlg::connectExtends()
{
    connect( mUseFromNowCheck, SIGNAL(clicked()), this, SLOT(clickUseFromNow()));
    connect( mCRLNumUseCheck, SIGNAL(clicked()), this, SLOT(clickCRLNum()));
    connect( mAKIUseCheck, SIGNAL(clicked()), this, SLOT(clickAKI()));
    connect( mIDPUseCheck, SIGNAL(clicked()), this, SLOT(clickIDP()));
    connect( mIANUseCheck, SIGNAL(clicked()), this, SLOT(clickIAN()));

    connect( mIDPAddBtn, SIGNAL(clicked()), this, SLOT(addIDP()));
    connect( mIANAddBtn, SIGNAL(clicked()), this, SLOT(addIAN()));

    connect( mIDPClearBtn, SIGNAL(clicked()), this, SLOT(clearIDP()));
    connect( mIANClearBtn, SIGNAL(clicked()), this, SLOT(clearIAN()));
}

void MakeCRLPolicyDlg::setExtends()
{
    clickCRLNum();
    clickAKI();
    clickIDP();
    clickIAN();
}

void MakeCRLPolicyDlg::setTableMenus()
{
    QStringList sDPNLabels = { "Type", "Value" };
    mIDPTable->setColumnCount(2);
    mIDPTable->horizontalHeader()->setStretchLastSection(true);
    mIDPTable->setHorizontalHeaderLabels(sDPNLabels);
    mIDPTable->verticalHeader()->setVisible(false);

    QStringList sIANLabels = { "Type", "Value" };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);
    mIANTable->verticalHeader()->setVisible(false);
}

void MakeCRLPolicyDlg::clickUseFromNow()
{
    bool bStatus = mUseFromNowCheck->isChecked();

    mValidDaysText->setEnabled( bStatus );
    mLastUpdateDateTime->setEnabled( !bStatus );
    mNextUpdateDateTime->setEnabled( !bStatus );
}

void MakeCRLPolicyDlg::clickCRLNum()
{
    bool bStatus = mCRLNumUseCheck->isChecked();

    mCRLNumCriticalCheck->setEnabled(bStatus);
    mCRLNumText->setEnabled(bStatus);
    mCRLNumAutoCheck->setEnabled(bStatus);
}

void MakeCRLPolicyDlg::clickAKI()
{
    bool bStatus = mAKIUseCheck->isChecked();

    mAKICriticalCheck->setEnabled(bStatus);
    mAKICertIssuerCheck->setEnabled(bStatus);
    mAKICertSerialCheck->setEnabled(bStatus);
}

void MakeCRLPolicyDlg::clickIDP()
{
    bool bStatus = mIDPUseCheck->isChecked();

    mIDPCriticalCheck->setEnabled(bStatus);
    mIDPAddBtn->setEnabled(bStatus);
    mIDPText->setEnabled(bStatus);
    mIDPTable->setEnabled(bStatus);
    mIDPCombo->setEnabled(bStatus);
}

void MakeCRLPolicyDlg::clickIAN()
{
    bool bStatus = mIANUseCheck->isChecked();

    mIANCriticalCheck->setEnabled(bStatus);
    mIANText->setEnabled(bStatus);
    mIANCombo->setEnabled(bStatus);
    mIANTable->setEnabled(bStatus);
    mIANAddBtn->setEnabled(bStatus);
}

void MakeCRLPolicyDlg::addIDP()
{
    QString strType = mIDPCombo->currentText();
    QString strVal = mIDPText->text();

    int row = mIDPTable->rowCount();
    mIDPTable->setRowCount( row + 1 );

    mIDPTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mIDPTable->setItem( row, 1, new QTableWidgetItem( strVal ));
}

void MakeCRLPolicyDlg::addIAN()
{
    QString strType = mIANCombo->currentText();
    QString strVal = mIANText->text();

    int row = mIANTable->rowCount();
    mIANTable->setRowCount( row + 1 );

    mIANTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mIANTable->setItem( row, 1, new QTableWidgetItem( strVal ));
}

void MakeCRLPolicyDlg::clearIDP()
{
    int nCnt = mIDPTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mIDPTable->removeRow(0);
}

void MakeCRLPolicyDlg::clearIAN()
{
    int nCnt = mIANTable->rowCount();

    for( int i=0; i < nCnt; i++)
        mIANTable->removeRow(0);
}

void MakeCRLPolicyDlg::saveCRLNumUse( int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "crlNumber" );
    policyExt.setCritical( mCRLNumCriticalCheck->isChecked() );

    QString strVal;

    if( mCRLNumAutoCheck->isChecked() )
        strVal = "auto";
    else {
        strVal = mCRLNumText->text();
    }

    policyExt.setValue( strVal );
    dbMgr->addCRLPolicyExtension( policyExt );
}

void MakeCRLPolicyDlg::saveAKIUse( int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "authorityKeyIdentifier" );
    policyExt.setCritical( mAKICriticalCheck->isChecked() );

    QString strVal;

    if( mAKICertIssuerCheck->isChecked() )
        strVal += "ISSUER#";

    if( mAKICertSerialCheck->isChecked() )
        strVal += "SERIAL#";

    policyExt.setValue( strVal );
    dbMgr->addCRLPolicyExtension(policyExt);
}

void MakeCRLPolicyDlg::saveIDPUse( int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "issuingDistributionPoint" );
    policyExt.setCritical( mIDPCriticalCheck->isChecked() );

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

    policyExt.setValue(strVal);
    dbMgr->addCRLPolicyExtension(policyExt);
}

void MakeCRLPolicyDlg::saveIANUse( int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "issuerAltName" );
    policyExt.setCritical( mIANCriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCRLPolicyExtension(policyExt);
}

void MakeCRLPolicyDlg::setCRLNumUse( PolicyExtRec& policyRec )
{
    mCRLNumUseCheck->setChecked(true);
    mCRLNumCriticalCheck->setChecked(policyRec.isCritical());
    clickCRLNum();

    QString strVal = policyRec.getValue();

    if( strVal == "auto" )
        mCRLNumAutoCheck->setChecked(true);
    else
        mCRLNumText->setText( strVal );
}

void MakeCRLPolicyDlg::setAKIUse( PolicyExtRec& policyRec )
{
    mAKIUseCheck->setChecked(true);
    mAKICriticalCheck->setChecked(policyRec.isCritical());
    clickAKI();

    QString strVal = policyRec.getValue();

    mAKICertIssuerCheck->setChecked( strVal.contains("ISSUER") );
    mAKICertSerialCheck->setChecked( strVal.contains("SERIAL") );
}

void MakeCRLPolicyDlg::setIDPUse( PolicyExtRec& policyRec )
{
    mIDPUseCheck->setChecked(true);
    mIDPCriticalCheck->setChecked(policyRec.isCritical());
    clickIDP();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");
    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);

        QStringList infoList = info.split("$");
        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mIDPTable->insertRow(i);
        mIDPTable->setItem(i, 0, new QTableWidgetItem(strType));
        mIDPTable->setItem(i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCRLPolicyDlg::setIANUse( PolicyExtRec& policyRec )
{
    mIANUseCheck->setChecked(true);
    mIANCriticalCheck->setChecked(policyRec.isCritical());
    clickIAN();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);

        QStringList infoList = info.split("$");
        if( infoList.size() < 2 ) continue;

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mIANTable->insertRow(i);
        mIANTable->setItem( i, 0, new QTableWidgetItem(strType));
        mIANTable->setItem( i, 1, new QTableWidgetItem(strData));
    }
}
