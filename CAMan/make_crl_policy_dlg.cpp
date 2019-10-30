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
        crlPolicyRec.setThisUpdate(0);
        crlPolicyRec.setNextUpdate(mValidDaysText->text().toLong());
    }
    else {
        QDateTime thisTime;
        QDateTime nextTime;

        thisTime.setDate( mThisUpdateDateTime->date() );
        nextTime.setDate( mNextUpdateDateTime->date() );

        crlPolicyRec.setThisUpdate( thisTime.toTime_t() );
        crlPolicyRec.setNextUpdate( nextTime.toTime_t() );
    }

    crlPolicyRec.setHash( mHashCombo->currentText() );
    dbMgr->addCRLPolicyRec( crlPolicyRec );


    /* need to set extend fields here */

    if( mCRLNumUseCheck->isChecked() ) setCRLNumUse( nPolicyNum );
    if( mDPNUseCheck->isChecked() ) setDPNUse( nPolicyNum );
    if( mAKIUseCheck->isChecked() ) setAKIUse( nPolicyNum );
    if( mIANUseCheck->isChecked() ) setIANUse( nPolicyNum );

    /* ....... */

    QDialog::accept();
}

void MakeCRLPolicyDlg::initUI()
{
    mHashCombo->addItems(sHashList);
    mDPNCombo->addItems(sTypeList);
    mIANCombo->addItems(sTypeList);
    mVersionCombo->addItems(sVersionList);
}

void MakeCRLPolicyDlg::connectExtends()
{
    connect( mCRLNumUseCheck, SIGNAL(clicked()), this, SLOT(clickCRLNum()));
    connect( mAKIUseCheck, SIGNAL(clicked()), this, SLOT(clickAKI()));
    connect( mDPNUseCheck, SIGNAL(clicked()), this, SLOT(clickDPN()));
    connect( mIANUseCheck, SIGNAL(clicked()), this, SLOT(clickIAN()));

    connect( mDPNAddBtn, SIGNAL(clicked()), this, SLOT(addDPN()));
    connect( mIANAddBtn, SIGNAL(clicked()), this, SLOT(addIAN()));
}

void MakeCRLPolicyDlg::setExtends()
{
    clickCRLNum();
    clickAKI();
    clickDPN();
    clickIAN();
}

void MakeCRLPolicyDlg::setTableMenus()
{
    QStringList sDPNLabels = { "Type", "Value" };
    mDPNTable->setColumnCount(2);
    mDPNTable->horizontalHeader()->setStretchLastSection(true);
    mDPNTable->setHorizontalHeaderLabels(sDPNLabels);

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

void MakeCRLPolicyDlg::clickDPN()
{
    bool bStatus = mDPNUseCheck->isChecked();

    mDPNCriticalCheck->setEnabled(bStatus);
    mDPNAddBtn->setEnabled(bStatus);
    mDPNText->setEnabled(bStatus);
    mDPNTable->setEnabled(bStatus);
    mDPNCombo->setEnabled(bStatus);
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

void MakeCRLPolicyDlg::addDPN()
{
    QString strType = mDPNCombo->currentText();
    QString strVal = mDPNText->text();

    int row = mDPNTable->rowCount();
    mDPNTable->setRowCount( row + 1 );

    mDPNTable->setItem( row, 0, new QTableWidgetItem( strType ));
    mDPNTable->setItem( row, 1, new QTableWidgetItem( strVal ));
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

}

void MakeCRLPolicyDlg::setAKIUse( int nPolicyNum )
{

}

void MakeCRLPolicyDlg::setDPNUse( int nPolicyNum )
{

}

void MakeCRLPolicyDlg::setIANUse( int nPolicyNum )
{

}
