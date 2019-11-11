#include "make_cert_policy_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cert_policy_rec.h"
#include "policy_ext_rec.h"
#include "db_mgr.h"
#include "commons.h"


MakeCertPolicyDlg::MakeCertPolicyDlg(QWidget *parent) :
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

MakeCertPolicyDlg::~MakeCertPolicyDlg()
{

}

void MakeCertPolicyDlg::setEdit(bool is_edit)
{
    is_edit_ = is_edit;
}

void MakeCertPolicyDlg::setPolicyNum(int policy_num)
{
    policy_num_ = policy_num;
}

void MakeCertPolicyDlg::showEvent(QShowEvent *event)
{
    initialize();


}

void MakeCertPolicyDlg::initialize()
{
    mCertTab->setCurrentIndex(0);

    if( is_edit_ )
        loadPolicy();
    else
        defaultPolicy();
}

void MakeCertPolicyDlg::loadPolicy()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertPolicyRec certPolicy;
    QDateTime notBefore;
    QDateTime notAfter;

    dbMgr->getCertPolicyRec( policy_num_, certPolicy );

    mNameText->setText( certPolicy.getName() );
    mVersionCombo->setCurrentIndex( certPolicy.getVersion() );
    mHashCombo->setCurrentText( certPolicy.getHash() );
    mSubjectDNText->setText( certPolicy.getDNTemplate() );

    if( certPolicy.getNotBefore() == 0 )
    {
        mUseDaysCheck->setChecked(true);
        mDaysText->setText( QString("%1").arg(certPolicy.getNotAfter()));
    }
    else {
        notBefore.setTime_t( certPolicy.getNotBefore() );
        notAfter.setTime_t( certPolicy.getNotAfter() );

        mNotBeforeDateTime->setDateTime( notBefore );
        mNotAfterDateTime->setDateTime( notAfter );
    }


    QList<PolicyExtRec> extPolicyList;
    dbMgr->getCertPolicyExtensionList( policy_num_, extPolicyList );

    for( int i=0; i < extPolicyList.size(); i++ )
    {
        PolicyExtRec extPolicy = extPolicyList.at(i);

        if( extPolicy.getSN() == kExtNameAIA )
            setAIAUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameAKI )
            setAKIUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameBC )
            setBCUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameCRLDP )
            setCRLDPUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameEKU )
            setEKUUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameIAN )
            setIANUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameKeyUsage )
            setKeyUsageUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameNC )
            setNCUse( extPolicy );
        else if( extPolicy.getSN() == kExtNamePolicy )
            setPolicyUse( extPolicy );
        else if( extPolicy.getSN() == kExtNamePC )
            setPCUse( extPolicy );
        else if( extPolicy.getSN() == kExtNamePM )
            setPMUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameSKI )
            setSKIUse( extPolicy );
        else if( extPolicy.getSN() == kExtNameSAN )
            setSANUse( extPolicy );
    }

}

void MakeCertPolicyDlg::defaultPolicy()
{
    int rowCnt = 0;
    mNameText->setText("");


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
}

void MakeCertPolicyDlg::accept()
{
    CertPolicyRec certPolicyRec;
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();

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

    int nPolicyNum = dbMgr->getCertPolicyNextNum();

    certPolicyRec.setNum( nPolicyNum );
    certPolicyRec.setVersion( mVersionCombo->currentIndex() );
    certPolicyRec.setName( strName );
    certPolicyRec.setDNTemplate( strSubjectDN );

    if( mUseDaysCheck->isChecked() )
    {
        certPolicyRec.setNotBefore(0);
        certPolicyRec.setNotAfter( mDaysText->text().toLong());
    }
    else {
        QDateTime beforeTime;
        QDateTime afterTime;

        beforeTime.setDate( mNotBeforeDateTime->date() );
        afterTime.setDate( mNotAfterDateTime->date() );

        certPolicyRec.setNotBefore( beforeTime.toTime_t() );
        certPolicyRec.setNotAfter( afterTime.toTime_t() );
    }

    certPolicyRec.setHash( mHashCombo->currentText() );

    if( is_edit_ )
    {
        dbMgr->modCertPolicyRec( policy_num_, certPolicyRec );
        dbMgr->delCertPolicyExtensionList( policy_num_ );
        nPolicyNum = policy_num_;
    }
    else
    {
        dbMgr->addCertPolicyRec( certPolicyRec );
    }

    /* need to set extend fields here */
    if( mAIAUseCheck->isChecked() ) saveAIAUse( nPolicyNum );
    if( mAKIUseCheck->isChecked() ) saveAKIUse( nPolicyNum );
    if( mBCUseCheck->isChecked() ) saveBCUse( nPolicyNum );
    if( mCRLDPUseCheck->isChecked() ) saveCRLDPUse( nPolicyNum );
    if( mEKUUseCheck->isChecked() ) saveEKUUse( nPolicyNum );
    if( mIANUseCheck->isChecked() ) saveIANUse( nPolicyNum );
    if( mKeyUsageUseCheck->isChecked() ) saveKeyUsageUse( nPolicyNum );
    if( mNCUseCheck->isChecked() ) saveNCUse( nPolicyNum );
    if( mPolicyUseCheck->isChecked() ) savePolicyUse( nPolicyNum );
    if( mPCUseCheck->isChecked() ) savePCUse( nPolicyNum );
    if( mPMUseCheck->isChecked() ) savePMUse( nPolicyNum );
    if( mSKIUseCheck->isChecked() ) saveSKIUse( nPolicyNum );
    if( mSANUseCheck->isChecked() ) saveSANUse( nPolicyNum );
    /* ....... */

    QDialog::accept();
}

void MakeCertPolicyDlg::initUI()
{
    mKeyUsageCombo->addItems(kKeyUsageList);
    mEKUCombo->addItems(kExtKeyUsageList);
    mVersionCombo->addItems(kCertVersionList);
    mCRLDPCombo->addItems(kTypeList);
    mAIATargetCombo->addItems( kAIATargetList );
    mAIATypeCombo->addItems(kTypeList);
    mSANCombo->addItems(kTypeList);
    mIANCombo->addItems(kTypeList);
    mNCTypeCombo->addItems(kTypeList);
    mNCSubCombo->addItems(kNCSubList);
    mBCCombo->addItems(kBCTypeList);
    mHashCombo->addItems(kHashList);
}

void MakeCertPolicyDlg::setTableMenus()
{
    QStringList sPolicyLabels = { "OID", "CPS", "UserNotice" };
    mPolicyTable->setColumnCount(3);
    mPolicyTable->horizontalHeader()->setStretchLastSection(true);
    mPolicyTable->setHorizontalHeaderLabels( sPolicyLabels );

    QStringList sCRLDPLabels = { "Type", "Value" };
    mCRLDPTable->setColumnCount(2);
    mCRLDPTable->horizontalHeader()->setStretchLastSection(true);
    mCRLDPTable->setHorizontalHeaderLabels(sCRLDPLabels);

    QStringList sAIALabels = { "Target", "Type", "Value" };
    mAIATable->setColumnCount(3);
    mAIATable->horizontalHeader()->setStretchLastSection(true);
    mAIATable->setHorizontalHeaderLabels(sAIALabels);

    QStringList sSANLabels = { "Type", "Value" };
    mSANTable->setColumnCount(2);
    mSANTable->horizontalHeader()->setStretchLastSection(true);
    mSANTable->setHorizontalHeaderLabels(sSANLabels);

    QStringList sIANLabels = { "Type", "Value" };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);

    QStringList sPMLabels = { "Tareg", "Value", "Target", "Value" };
    mPMTable->setColumnCount(4);
    mPMTable->horizontalHeader()->setStretchLastSection(true);
    mPMTable->setHorizontalHeaderLabels(sPMLabels);

    QStringList sNCLabels = { "Type", "Target", "Value", "Min", "Max" };
    mNCTable->setColumnCount(5);
    mNCTable->horizontalHeader()->setStretchLastSection(true);
    mNCTable->setHorizontalHeaderLabels(sNCLabels);
}

void MakeCertPolicyDlg::connectExtends()
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
}

void MakeCertPolicyDlg::clickUseCSR()
{
    bool bStatus = mUseCSRCheck->isChecked();

    mSubjectDNText->setEnabled( !bStatus );

    if( bStatus )
        mSubjectDNText->setText( "#CSR" );
    else {
        mSubjectDNText->setText( "" );
    }
}

void MakeCertPolicyDlg::clickUseDays()
{
    bool bStatus = mUseDaysCheck->isChecked();

    mDaysText->setEnabled(bStatus);
    mNotAfterDateTime->setEnabled(!bStatus);
    mNotBeforeDateTime->setEnabled(!bStatus);
}

void MakeCertPolicyDlg::setExtends()
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


void MakeCertPolicyDlg::clickAIAUse()
{
    bool bStatus = mAIAUseCheck->isChecked();

    mAIACriticalCheck->setEnabled(bStatus);
    mAIAAddBtn->setEnabled(bStatus);
    mAIATypeCombo->setEnabled(bStatus);
    mAIATargetCombo->setEnabled(bStatus);
    mAIAText->setEnabled(bStatus);
    mAIATable->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickAKIUse()
{
    bool bStatus = mAKIUseCheck->isChecked();

    mAKICriticalCheck->setEnabled(bStatus);
    mAKICertIssuerCheck->setEnabled(bStatus);
    mAKICertSerialCheck->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickBCUse()
{
    bool bStatus = mBCUseCheck->isChecked();

    mBCCriticalCheck->setEnabled(bStatus);
    mBCCombo->setEnabled(bStatus);
    mBCPathLenText->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickCRLDPUse()
{
    bool bStatus = mCRLDPUseCheck->isChecked();

    mCRLDPCriticalCheck->setEnabled( bStatus );
    mCRLDPCombo->setEnabled(bStatus);
    mCRLDPAddBtn->setEnabled(bStatus);
    mCRLDPText->setEnabled(bStatus);
    mCRLDPTable->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickEKUUse()
{
    bool bStatus = mEKUUseCheck->isChecked();

    mEKUCriticalCheck->setEnabled( bStatus );
    mEKUCombo->setEnabled(bStatus);
    mEKUAddBtn->setEnabled(bStatus);
    mEKUList->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickIANUse()
{
    bool bStatus = mIANUseCheck->isChecked();

    mIANCriticalCheck->setEnabled(bStatus);
    mIANCombo->setEnabled(bStatus);
    mIANText->setEnabled(bStatus);
    mIANTable->setEnabled(bStatus);
    mIANAddBtn->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickKeyUsageUse()
{
    bool bStatus = mKeyUsageUseCheck->isChecked();

    mKeyUsageCriticalCheck->setEnabled( bStatus );
    mKeyUsageCombo->setEnabled( bStatus );
    mKeyUsageAddBtn->setEnabled( bStatus );
    mKeyUsageList->setEnabled( bStatus );
}

void MakeCertPolicyDlg::clickNCUse()
{
    bool bStatus = mNCUseCheck->isChecked();

    mNCCriticalCheck->setEnabled(bStatus);
    mNCSubCombo->setEnabled(bStatus);
    mNCAddBtn->setEnabled(bStatus);
    mNCTypeCombo->setEnabled(bStatus);
    mNCSubText->setEnabled(bStatus);
    mNCMaxText->setEnabled(bStatus);
    mNCMinText->setEnabled(bStatus);
    mNCTable->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickPolicyUse()
{
    bool bStatus = mPolicyUseCheck->isChecked();

    mPolicyCriticalCheck->setEnabled( bStatus );
    mPolicyAddBtn->setEnabled( bStatus );
    mPolicyOIDText->setEnabled( bStatus );
    mPolicyCPSText->setEnabled( bStatus );
    mPolicyUserNoticeText->setEnabled( bStatus );
    mPolicyTable->setEnabled( bStatus );
}

void MakeCertPolicyDlg::clickPCUse()
{
    bool bStatus = mPCUseCheck->isChecked();

    mPCCriticalCheck->setEnabled(bStatus);
    mPCInhibitText->setEnabled(bStatus);
    mPCExplicitText->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickPMUse()
{
    bool bStatus = mPMUseCheck->isChecked();

    mPMCriticalCheck->setEnabled(bStatus);
    mPMAddBtn->setEnabled(bStatus);
    mPMIssuerDomainPolicyText->setEnabled(bStatus);
    mPMSubjectDomainPolicyText->setEnabled(bStatus);
    mPMTable->setEnabled(bStatus);
}

void MakeCertPolicyDlg::clickSKIUse()
{
    bool bStatus = mSKIUseCheck->isChecked();

    mSKICriticalCheck->setEnabled( bStatus );
}

void MakeCertPolicyDlg::clickSANUse()
{
    bool bStatus = mSANUseCheck->isChecked();

    mSANCriticalCheck->setEnabled(bStatus);
    mSANCombo->setEnabled(bStatus);
    mSANAddBtn->setEnabled(bStatus);
    mSANText->setEnabled(bStatus);
    mSANTable->setEnabled(bStatus);
}


void MakeCertPolicyDlg::addKeyUsage()
{
    QString strVal = mKeyUsageCombo->currentText();

    mKeyUsageList->addItem( strVal );
}

void MakeCertPolicyDlg::addPolicy()
{
    QString strOID = mPolicyOIDText->text();
    QString strCPS = mPolicyCPSText->text();
    QString strUserNotice = mPolicyUserNoticeText->text();

    int row = mPolicyTable->rowCount();

    mPolicyTable->setRowCount( row + 1 );

    mPolicyTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mPolicyTable->setItem( row, 1, new QTableWidgetItem(strCPS));
    mPolicyTable->setItem( row, 2, new QTableWidgetItem(strUserNotice));
}

void MakeCertPolicyDlg::addEKU()
{
    QString strVal = mEKUCombo->currentText();

    mEKUList->addItem( strVal );
}

void MakeCertPolicyDlg::addCRLDP()
{
    QString strType = mCRLDPCombo->currentText();
    QString strVal = mCRLDPText->text();

    int row = mCRLDPTable->rowCount();
    mCRLDPTable->setRowCount( row + 1 );

    mCRLDPTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mCRLDPTable->setItem( row, 1, new QTableWidgetItem( strVal ));
}

void MakeCertPolicyDlg::addAIA()
{
    QString strTarget = mAIATargetCombo->currentText();
    QString strType = mAIATypeCombo->currentText();
    QString strVal = mAIAText->text();

    int row = mAIATable->rowCount();

    mAIATable->setRowCount( row + 1 );

    mAIATable->setItem( row, 0, new QTableWidgetItem( strTarget ));
    mAIATable->setItem( row, 1, new QTableWidgetItem( strType) );
    mAIATable->setItem( row, 2, new QTableWidgetItem( strVal ));
}

void MakeCertPolicyDlg::addSAN()
{
    QString strType = mSANCombo->currentText();
    QString strVal = mSANText->text();

    int row = mSANTable->rowCount();
    mSANTable->setRowCount( row + 1 );

    mSANTable->setItem( row, 0, new QTableWidgetItem(strType));
    mSANTable->setItem( row, 1, new QTableWidgetItem(strVal));
}

void MakeCertPolicyDlg::addIAN()
{
    QString strType = mIANCombo->currentText();
    QString strVal = mIANText->text();

    int row = mIANTable->rowCount();
    mIANTable->setRowCount( row + 1 );

    mIANTable->setItem( row, 0, new QTableWidgetItem(strType));
    mIANTable->setItem( row, 1, new QTableWidgetItem(strVal));
}

void MakeCertPolicyDlg::addPM()
{
    QString strIDP = mPMIssuerDomainPolicyText->text();
    QString strSDP = mPMSubjectDomainPolicyText->text();

    int row = mPMTable->rowCount();
    mPMTable->setRowCount( row + 1 );

    mPMTable->setItem( row, 0, new QTableWidgetItem( "IssuerDomainPolicy"));
    mPMTable->setItem( row, 1, new QTableWidgetItem( strIDP));
    mPMTable->setItem( row, 2, new QTableWidgetItem( "SubjectDomainPolicy"));
    mPMTable->setItem( row, 3, new QTableWidgetItem( strSDP));
}

void MakeCertPolicyDlg::addNC()
{
    QString strType = mNCTypeCombo->currentText();
    QString strSubType = mNCSubCombo->currentText();
    QString strVal = mNCSubText->text();
    QString strMax = mNCMaxText->text();
    QString strMin = mNCMinText->text();

    int row = mNCTable->rowCount();
    mNCTable->setRowCount( row + 1 );

    mNCTable->setItem( row, 0, new QTableWidgetItem(strType));
    mNCTable->setItem( row, 1, new QTableWidgetItem(strSubType));
    mNCTable->setItem( row, 2, new QTableWidgetItem(strVal));
    mNCTable->setItem( row, 3, new QTableWidgetItem(strMax));
    mNCTable->setItem( row, 4, new QTableWidgetItem(strMin));
}

void MakeCertPolicyDlg::saveAIAUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "authorityInfoAccess" );
    policyExt.setCritical( mAIACriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension(policyExt);
}

void MakeCertPolicyDlg::saveAKIUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "authorityKeyIdentifier" );
    policyExt.setCritical( mAKICriticalCheck->isChecked() );

    QString strVal;

    if( mAKICertIssuerCheck->isChecked() ) strVal += "ISSUER#";
    if( mAKICertSerialCheck->isChecked() ) strVal += "SERIAL#";

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveBCUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN("basicConstraints");
    policyExt.setCritical( mBCCriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveCRLDPUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "crlDistributionPoints");
    policyExt.setCritical( mCRLDPCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; mCRLDPTable->rowCount(); i++ )
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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveEKUUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "extendedKeyUsage");
    policyExt.setCritical( mEKUCriticalCheck->isChecked() );

    QString strVal = "";

    for( int i=0; i < mEKUList->count(); i++ )
    {
        if( i != 0 ) strVal += "#";
        strVal += mEKUList->item(i)->text();
    }

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveIANUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "issuerAltName" );
    policyExt.setCritical( mIANCriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveKeyUsageUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "keyUsage");
    policyExt.setCritical( mKeyUsageCriticalCheck->isChecked() );

    QString strValue;

    for( int i =0; i < mKeyUsageList->count(); i++ )
    {
        if( i != 0 ) strValue += "#";
        strValue += mKeyUsageList->item(i)->text();
    }

    policyExt.setValue( strValue );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveNCUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "nameConstraints" );
    policyExt.setCritical( mNCCriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::savePolicyUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "certificatePolicies" );
    policyExt.setCritical( mPolicyCriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::savePCUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "policyConstraints" );
    policyExt.setCritical( mPCCriticalCheck->isChecked() );

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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension(policyExt);
}

void MakeCertPolicyDlg::savePMUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "policyMappings" );
    policyExt.setCritical( mPMCriticalCheck->isChecked() );

    QString strVal;

    for( int i=0; mPMTable->rowCount(); i++ )
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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::saveSKIUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "subjectKeyIdentifier" );
    policyExt.setCritical( mSKICriticalCheck->isChecked() );

    dbMgr->addCertPolicyExtension(policyExt);
}

void MakeCertPolicyDlg::saveSANUse(int nPolicyNum)
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
    policyExt.setSN( "subjectAltName" );
    policyExt.setCritical( mSANCriticalCheck->isChecked() );

    QString strVal = "";
    for( int i=0; mSANTable->rowCount(); i++ )
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

    policyExt.setValue( strVal );
    dbMgr->addCertPolicyExtension( policyExt );
}

void MakeCertPolicyDlg::setAIAUse( PolicyExtRec& policyRec )
{
    mAIAUseCheck->setChecked(true);
    mAIACriticalCheck->setChecked(policyRec.isCritical());
    clickAIAUse();

    QString strVal = policyRec.getValue();

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
        mAIATable->setItem( i, 0, new QTableWidgetItem(strMethod));
        mAIATable->setItem( i, 1, new QTableWidgetItem(strType));
        mAIATable->setItem( i, 2, new QTableWidgetItem(strData));
    }
}

void MakeCertPolicyDlg::setAKIUse( PolicyExtRec& policyRec )
{
    mAKIUseCheck->setChecked(true);
    mAKICriticalCheck->setChecked( policyRec.isCritical() );
    clickAKIUse();

    QString strVal = policyRec.getValue();

    bool bStatus = strVal.contains("ISSUER");
    mAKICertIssuerCheck->setChecked(bStatus);

    bStatus = strVal.contains("SERIAL");
    mAKICertSerialCheck->setChecked(bStatus);
}

void MakeCertPolicyDlg::setBCUse( PolicyExtRec& policyRec )
{
    mBCUseCheck->setChecked(true);
    mBCCriticalCheck->setChecked(policyRec.isCritical());
    clickBCUse();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");
    QString strType= valList.at(0);
    QString strLen = valList.at(1);

    mBCCombo->setCurrentText( strType );
    mBCPathLenText->setText( strLen );
}

void MakeCertPolicyDlg::setCRLDPUse( PolicyExtRec& policyRec )
{
    mCRLDPUseCheck->setChecked(true);
    mCRLDPCriticalCheck->setChecked(policyRec.isCritical());
    clickCRLDPUse();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList typeData = info.split("$");

        QString strType = typeData.at(0);
        QString strData = typeData.at(1);

        mCRLDPTable->insertRow(i);
        mCRLDPTable->setItem( i, 0, new QTableWidgetItem(strType));
        mCRLDPTable->setItem( i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCertPolicyDlg::setEKUUse( PolicyExtRec& policyRec )
{
    QString strVal = "";

    mEKUUseCheck->setChecked(true);
    mEKUCriticalCheck->setChecked(policyRec.isCritical());
    clickEKUUse();

    strVal = policyRec.getValue();
    QStringList valList = strVal.split("#");

    if( valList.size() > 0 ) mEKUList->insertItems( 0, valList );
}

void MakeCertPolicyDlg::setIANUse( PolicyExtRec& policyRec )
{
    mIANUseCheck->setChecked(true);
    mIANCriticalCheck->setChecked(policyRec.isCritical());
    clickIANUse();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mIANTable->insertRow(i);
        mIANTable->setItem( i, 0, new QTableWidgetItem(strType));
        mIANTable->setItem(i, 1, new QTableWidgetItem(strData));
    }
}

void MakeCertPolicyDlg::setKeyUsageUse( PolicyExtRec& policyRec )
{
    mKeyUsageUseCheck->setChecked(true);
    mKeyUsageCriticalCheck->setChecked( policyRec.isCritical() );
    clickKeyUsageUse();

    QString strVal = policyRec.getValue();

    mKeyUsageList->clear();

    QStringList valList = strVal.split("#");
    if( valList.size() > 0 ) mKeyUsageList->insertItems(0, valList );
}

void MakeCertPolicyDlg::setNCUse( PolicyExtRec& policyRec )
{
    mNCUseCheck->setChecked(true);
    mNCCriticalCheck->setChecked(policyRec.isCritical());
    clickNCUse();

    QString strVal = policyRec.getValue();

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
        mNCTable->setItem(i, 0, new QTableWidgetItem(strType));
        mNCTable->setItem(i, 1, new QTableWidgetItem(strKind));
        mNCTable->setItem(i, 2, new QTableWidgetItem(strData));
        mNCTable->setItem(i, 3, new QTableWidgetItem(strMin));
        mNCTable->setItem(i, 4, new QTableWidgetItem(strMax));
    }
}

void MakeCertPolicyDlg::setPolicyUse( PolicyExtRec& policyRec )
{
    mPolicyUseCheck->setChecked(true);
    mPolicyCriticalCheck->setChecked(policyRec.isCritical());
    clickPolicyUse();

    QString strVal = policyRec.getValue();

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

        mPolicyTable->setItem( row, 0, new QTableWidgetItem(strOID));
        mPolicyTable->setItem( row, 1, new QTableWidgetItem(strCPS));
        mPolicyTable->setItem( row, 2, new QTableWidgetItem(strUserNotice));
    }
}

void MakeCertPolicyDlg::setPCUse( PolicyExtRec& policyRec )
{
    mPCUseCheck->setChecked(true);
    mPCCriticalCheck->setChecked(policyRec.isCritical());
    clickPCUse();

    QString strVal = policyRec.getValue();
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

void MakeCertPolicyDlg::setPMUse( PolicyExtRec& policyRec )
{
    mPMUseCheck->setChecked(true);
    mPMCriticalCheck->setChecked(policyRec.isCritical());
    clickPMUse();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        QString strIDP = infoList.at(0);
        QString strSDP = infoList.at(1);

        mPMTable->insertRow(i);
        mPMTable->setItem(i,0,new QTableWidgetItem("issuerDomainPolicy"));
        mPMTable->setItem(i,1,new QTableWidgetItem(strIDP));
        mPMTable->setItem(i,2,new QTableWidgetItem("subjectDomainPolicy"));
        mPMTable->setItem(i,3,new QTableWidgetItem(strSDP));
    }
}

void MakeCertPolicyDlg::setSKIUse( PolicyExtRec& policyRec )
{
    mSKIUseCheck->setChecked(true);
    mSKICriticalCheck->setChecked(policyRec.isCritical());
    clickSKIUse();
}

void MakeCertPolicyDlg::setSANUse( PolicyExtRec& policyRec )
{
    mSANUseCheck->setChecked(true);
    mSANCriticalCheck->setChecked(policyRec.isCritical());
    clickSANUse();

    QString strVal = policyRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        mSANTable->insertRow(i);
        mSANTable->setItem( i, 0, new QTableWidgetItem(strType));
        mSANTable->setItem(i, 1, new QTableWidgetItem(strData));
    }
}
