#include "make_crl_policy_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "policy_ext_rec.h"
#include "crl_policy_rec.h"
#include "db_mgr.h"

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
}

MakeCRLPolicyDlg::~MakeCRLPolicyDlg()
{

}


void MakeCRLPolicyDlg::showEvent(QShowEvent *event)
{

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
    dbMgr->addCRLPolicyRec( crlPolicyRec );


    /* need to set extend fields here */

    if( mCRLNumUseCheck->isChecked() ) setCRLNumUse( nPolicyNum );
    if( mIDPUseCheck->isChecked() ) setIDPUse( nPolicyNum );
    if( mAKIUseCheck->isChecked() ) setAKIUse( nPolicyNum );
    if( mIANUseCheck->isChecked() ) setIANUse( nPolicyNum );

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

void MakeCRLPolicyDlg::setCRLNumUse( int nPolicyNum )
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

void MakeCRLPolicyDlg::setAKIUse( int nPolicyNum )
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

void MakeCRLPolicyDlg::setIDPUse( int nPolicyNum )
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

void MakeCRLPolicyDlg::setIANUse( int nPolicyNum )
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
