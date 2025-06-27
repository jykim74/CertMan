#include "view_cert_profile_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "settings_mgr.h"
#include "commons.h"

#include "js_gen.h"
#include "js_pki_ext.h"

ViewCertProfileDlg::ViewCertProfileDlg(QWidget *parent)
    : QDialog(parent)
{
    profile_num_ = -1;
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();

    mProfileToolBox->setCurrentIndex(0);

    mCloseBtn->setFocus();
}

ViewCertProfileDlg::~ViewCertProfileDlg()
{

}

void ViewCertProfileDlg::initUI()
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
    mCRLDPTable->setColumnWidth(0,60);

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
    mPMTable->setColumnWidth(0,160);
    mPMTable->setColumnWidth(1,160);
    mPMTable->setColumnWidth(2,160);

    QStringList sNCLabels = { tr("Type"), tr("Target"), tr("Value"), tr("Min"), tr("Max") };
    mNCTable->setColumnCount(5);
    mNCTable->horizontalHeader()->setStretchLastSection(true);
    mNCTable->setHorizontalHeaderLabels(sNCLabels);
    mNCTable->verticalHeader()->setVisible(false);
    mNCTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mNCTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mNCTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mNCTable->setColumnWidth(0,60);
    mNCTable->setColumnWidth(3,40);
    mNCTable->setColumnWidth(4,40);


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

void ViewCertProfileDlg::initialize()
{

}

void ViewCertProfileDlg::setAIAUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setBCUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setCRLDPUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setEKUUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setIANUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setKeyUsageUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setNCUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setPolicyUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setPCUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setPMUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setSKIUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setSANUse( ProfileExtRec& profileRec )
{

}

void ViewCertProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{

}

int ViewCertProfileDlg::setProfile( int nNum )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    profile_num_ = nNum;

    CertProfileRec certProfile;

    int nNotBefore = 0;
    int nNotAfter = 0;
    QString strNotBefore;
    QString strNotAfter;

    ret = dbMgr->getCertProfileRec( profile_num_, certProfile );
    if( ret < 0 )
    {
        manApplet->warningBox( tr( "fail to get certificate profile: %1" ).arg( ret ), this );
        return ret;
    }

    mNameText->setText( certProfile.getName() );

    nNotBefore = certProfile.getNotBefore();
    nNotAfter = certProfile.getNotAfter();

    if( nNotBefore == 0 )
    {
        strNotBefore = tr("Creation time");
        strNotAfter = tr( "%1 Days" ).arg( nNotAfter );
    }
    else if( nNotBefore == 1 )
    {
        strNotBefore = tr("Creation time");
        strNotAfter = tr( "%1 Months" ).arg( nNotAfter );
    }
    else if( nNotBefore == 2 )
    {
        strNotBefore = tr("Creation time");
        strNotAfter = tr( "%1 Years" ).arg( nNotAfter );
    }
    else
    {
        QDateTime notBefore;
        QDateTime notAfter;
        notBefore.setSecsSinceEpoch( nNotBefore );
        notAfter.setSecsSinceEpoch( nNotAfter );

        strNotBefore = notBefore.toString( "yyyy-MM-dd hh:mm:ss" );
        strNotAfter = notAfter.toString( "yyyy-MM-dd hh:mm:ss" );
    }

    mNotBeforeText->setText( strNotBefore );
    mNotAfterText->setText( strNotAfter );

    QList<ProfileExtRec> extProfileList;
    dbMgr->getCertProfileExtensionList( profile_num_, extProfileList );


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

    return 0;
}
