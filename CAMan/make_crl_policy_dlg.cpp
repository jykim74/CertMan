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

void MakeCRLPolicyDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void MakeCRLPolicyDlg::initialize()
{
    mCRLTab->setCurrentIndex(0);

    if( is_edit_ )
        loadPolicy();
    else
        defaultPolicy();
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
    mNameText->setText("");
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

    QDialog::accept();
}

void MakeCRLPolicyDlg::initUI()
{
    mHashCombo->addItems(sHashList);
    mIDPCombo->addItems(sTypeList);
    mIANCombo->addItems(sTypeList);
    mVersionCombo->addItems(sVersionList);
}

void MakeCRLPolicyDlg::connectExtends()
{
    connect( mCRLNumUseCheck, SIGNAL(clicked()), this, SLOT(clickCRLNum()));
    connect( mAKIUseCheck, SIGNAL(clicked()), this, SLOT(clickAKI()));
    connect( mIDPUseCheck, SIGNAL(clicked()), this, SLOT(clickIDP()));
    connect( mIANUseCheck, SIGNAL(clicked()), this, SLOT(clickIAN()));

    connect( mIDPAddBtn, SIGNAL(clicked()), this, SLOT(addIDP()));
    connect( mIANAddBtn, SIGNAL(clicked()), this, SLOT(addIAN()));
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

    QStringList sIANLabels = { "Type", "Value" };
    mIANTable->setColumnCount(2);
    mIANTable->horizontalHeader()->setStretchLastSection(true);
    mIANTable->setHorizontalHeaderLabels(sIANLabels);
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

void MakeCRLPolicyDlg::setCRLNumUse( const PolicyExtRec& policyRec )
{

}

void MakeCRLPolicyDlg::setAKIUse( const PolicyExtRec& policyRec )
{

}

void MakeCRLPolicyDlg::setIDPUse( const PolicyExtRec& policyRec )
{

}

void MakeCRLPolicyDlg::setIANUse( const PolicyExtRec& policyRec )
{

}
