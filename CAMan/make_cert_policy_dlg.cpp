#include "make_cert_policy_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cert_policy_rec.h"
#include "policy_ext_rec.h"
#include "db_mgr.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
static QStringList sKeyUsageList = {
    "digitalSignature", "nonRepudiation", "keyEncipherment",
    "dataEncipherment", "keyAgreement", "keyCertSign",
    "cRLSign", "encipherOnly", "decipherOnly"
};


static QStringList sExtKeyUsageList = {
    "serverAuth", "clientAuth", "codeSigning",
    "emailProtection", "timeStamping", "OCSPSigning",
    "ipsecIKE", "msCodeInd", "msCodeCom",
    "msCTLSign", "msEFS"
};

static QStringList sVersionList = { "V1", "V2", "V3" };

static QStringList sTypeList = { "URI", "email", "DNS" };

static QStringList sAIATargetList = { "OCSP", "caIssuer" };

static QStringList sNCSubList = { "permittedSubtrees", "excludedSubtrees" };

static QStringList sBCTypeList = { "CA", "End Entity" };


MakeCertPolicyDlg::MakeCertPolicyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    connectExtends();
    setExtends();
    setTableMenus();
}

MakeCertPolicyDlg::~MakeCertPolicyDlg()
{

}


void MakeCertPolicyDlg::showEvent(QShowEvent *event)
{

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
    dbMgr->addCertPolicyRec( certPolicyRec );

    /* need to set extend fields here */
    if( mAIAUseCheck->isChecked() ) setAIAUse( nPolicyNum );
    if( mAKIUseCheck->isChecked() ) setAKIUse( nPolicyNum );
    if( mBCUseCheck->isChecked() ) setBCUse( nPolicyNum );
    if( mCRLDPUseCheck->isChecked() ) setCRLDPUse( nPolicyNum );
    if( mEKUUseCheck->isChecked() ) setEKUUse( nPolicyNum );
    if( mIANUseCheck->isChecked() ) setIANUse( nPolicyNum );
    if( mKeyUsageUseCheck->isChecked() ) setKeyUsageUse( nPolicyNum );
    if( mNCUseCheck->isChecked() ) setNCUse( nPolicyNum );
    if( mPolicyUseCheck->isChecked() ) setPolicyUse( nPolicyNum );
    if( mPCUseCheck->isChecked() ) setPCUse( nPolicyNum );
    if( mPMUseCheck->isChecked() ) setPMUse( nPolicyNum );
    if( mSKIUseCheck->isChecked() ) setSKIUse( nPolicyNum );
    if( mSANUseCheck->isChecked() ) setSANUse( nPolicyNum );
    /* ....... */

    QDialog::accept();
}

void MakeCertPolicyDlg::initUI()
{
    mKeyUsageCombo->addItems(sKeyUsageList);
    mEKUCombo->addItems(sExtKeyUsageList);
    mVersionCombo->addItems(sVersionList);
    mCRLDPCombo->addItems(sTypeList);
    mAIATargetCombo->addItems( sAIATargetList );
    mAIATypeCombo->addItems(sTypeList);
    mSANCombo->addItems(sTypeList);
    mIANCombo->addItems(sTypeList);
    mNCTypeCombo->addItems(sTypeList);
    mNCSubCombo->addItems(sNCSubList);
    mBCCombo->addItems(sBCTypeList);
    mHashCombo->addItems(sHashList);
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

void MakeCertPolicyDlg::setAIAUse(int nPolicyNum )
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

void MakeCertPolicyDlg::setAKIUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}

void MakeCertPolicyDlg::setBCUse(int nPolicyNum )
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

void MakeCertPolicyDlg::setCRLDPUse(int nPolicyNum )
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

void MakeCertPolicyDlg::setEKUUse(int nPolicyNum )
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

void MakeCertPolicyDlg::setIANUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}

void MakeCertPolicyDlg::setKeyUsageUse(int nPolicyNum )
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

void MakeCertPolicyDlg::setNCUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}

void MakeCertPolicyDlg::setPolicyUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}

void MakeCertPolicyDlg::setPCUse(int nPolicyNum )
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

void MakeCertPolicyDlg::setPMUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}

void MakeCertPolicyDlg::setSKIUse(int nPolicyNum )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}

void MakeCertPolicyDlg::setSANUse(int nPolicyNum)
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    PolicyExtRec policyExt;

    policyExt.setPolicyNum(nPolicyNum);
}
