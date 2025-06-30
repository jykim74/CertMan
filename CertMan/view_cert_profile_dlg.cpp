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
    mProfileToolBox->layout()->setSpacing(5);
    mProfileToolBox->layout()->setMargin(5);

    mBase->layout()->setSpacing(5);
    mBase->layout()->setMargin(5);

    mExtension1->layout()->setSpacing(5);
    mExtension1->layout()->setMargin(5);

    mExtension2->layout()->setSpacing(5);
    mExtension2->layout()->setMargin(5);

    mExtension3->layout()->setSpacing(5);
    mExtension3->layout()->setMargin(5);

    mExtension4->layout()->setSpacing(5);
    mExtension4->layout()->setMargin(5);
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


    QStringList sNCLabels = { tr("Type"), tr("Target"), tr("Value"), tr("Min"), tr("Max") };
    mNCTable->setColumnCount(5);
    mNCTable->horizontalHeader()->setStretchLastSection(true);
    mNCTable->setHorizontalHeaderLabels(sNCLabels);
    mNCTable->verticalHeader()->setVisible(false);
    mNCTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mNCTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mNCTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mNCTable->setColumnWidth(0,60);
    mNCTable->setColumnWidth(2,160);


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

    mProfileToolBox->setStyleSheet( kToolBoxStyle );
    mProfileToolBox->setItemEnabled( 1, false );
    mProfileToolBox->setItemEnabled( 2, false );
    mProfileToolBox->setItemEnabled( 3, false );
    mProfileToolBox->setItemEnabled( 4, false );

    mProfileToolBox->setItemIcon( 0, QIcon( ":/images/cert_profile.png" ));
    mProfileToolBox->setItemIcon( 1, QIcon( ":/images/cert_profile.png" ));
    mProfileToolBox->setItemIcon( 2, QIcon( ":/images/cert_profile.png" ));
    mProfileToolBox->setItemIcon( 3, QIcon( ":/images/cert_profile.png" ));
    mProfileToolBox->setItemIcon( 4, QIcon( ":/images/cert_profile.png" ));

    setAllEnable(false);
}

void ViewCertProfileDlg::initialize()
{

}

void ViewCertProfileDlg::setAIAEnable( bool bVal )
{
    mAIACritLabel->setEnabled(bVal);
    mAIALabel->setEnabled( bVal );
    mAIATable->setEnabled( bVal );
}

void ViewCertProfileDlg::setAKIEnable( bool bVal )
{
    mAKICritLabel->setEnabled(bVal);
    mAKIIssuerLabel->setEnabled(bVal);
    mAKILabel->setEnabled(bVal);
    mAKISerialLabel->setEnabled(bVal);
    mAKISerialText->setEnabled(bVal);
    mAKIIssuerLabel->setEnabled(bVal);
    mAKIIssuerText->setEnabled(bVal);
}

void ViewCertProfileDlg::setBCEnable( bool bVal )
{
    mBCCritLabel->setEnabled(bVal);
    mBCLabel->setEnabled(bVal);
    mBCTargetLabel->setEnabled(bVal);
    mBCTargetText->setEnabled(bVal);
    mBCPathLenLabel->setEnabled(bVal);
    mBCPathLenText->setEnabled(bVal);
}

void ViewCertProfileDlg::setCRLDPEnable( bool bVal )
{
    mCRLDPCritLabel->setEnabled(bVal);
    mCRLDPLabel->setEnabled(bVal);
    mCRLDPTable->setEnabled(bVal);
}

void ViewCertProfileDlg::setEKUEnable( bool bVal )
{
    mEKUCritLabel->setEnabled(bVal);
    mEKULabel->setEnabled(bVal);
    mEKUText->setEnabled(bVal);
}

void ViewCertProfileDlg::setIANEnable( bool bVal )
{
    mIANCritLabel->setEnabled(bVal);
    mIANLabel->setEnabled(bVal);
    mIANTable->setEnabled(bVal);
}

void ViewCertProfileDlg::setKeyUsageEnable( bool bVal )
{
    mKeyUsageCritLabel->setEnabled(bVal);
    mKeyUsageLabel->setEnabled(bVal);
    mKeyUsageText->setEnabled(bVal);
}

void ViewCertProfileDlg::setNCEnable( bool bVal )
{
    mNCCritLabel->setEnabled(bVal);
    mNCLabel->setEnabled(bVal);
    mNCTable->setEnabled(bVal);
}

void ViewCertProfileDlg::setPolicyEnable( bool bVal )
{
    mPolicyCritLabel->setEnabled(bVal);
    mPolicyLabel->setEnabled(bVal);
    mPolicyTable->setEnabled(bVal);
}

void ViewCertProfileDlg::setPCEnable( bool bVal )
{
    mPCCritLabel->setEnabled(bVal);
    mPCLabel->setEnabled(bVal);
    mPC_REPLabel->setEnabled(bVal);
    mPC_REPText->setEnabled(bVal);
    mPC_IPMLabel->setEnabled(bVal);
    mPC_IPMText->setEnabled(bVal);
}

void ViewCertProfileDlg::setPMEnable( bool bVal )
{
    mPMCritLabel->setEnabled(bVal);
    mPMLabel->setEnabled(bVal);
    mPMTable->setEnabled(bVal);
}

void ViewCertProfileDlg::setSKIEnable( bool bVal )
{
    mSKICritLabel->setEnabled(bVal);
    mSKILabel->setEnabled(bVal);
    mSKIText->setEnabled(bVal);
}

void ViewCertProfileDlg::setSANEnable( bool bVal )
{
    mSANCritLabel->setEnabled(bVal);
    mSANLabel->setEnabled(bVal);
    mSANTable->setEnabled(bVal);
}

void ViewCertProfileDlg::setExtensionsEnable( bool bVal )
{
    if( bVal == false )
        mExtensionsGroup->hide();
    else
        mExtensionsGroup->show();

    mExtensionsGroup->setEnabled(bVal);
}

void ViewCertProfileDlg::setAllEnable( bool bVal )
{
    setAIAEnable( bVal );
    setAKIEnable( bVal );
    setBCEnable( bVal );
    setCRLDPEnable( bVal );
    setEKUEnable( bVal );
    setIANEnable( bVal );
    setKeyUsageEnable( bVal );
    setNCEnable( bVal );
    setPolicyEnable( bVal );
    setPCEnable( bVal );
    setPMEnable( bVal );
    setSKIEnable( bVal );
    setSANEnable( bVal );
    setExtensionsEnable(bVal);
}

void ViewCertProfileDlg::setAIAUse( ProfileExtRec& profileRec )
{
    if( mAIALabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 2, true );
        setAIAEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mAIACritLabel->setText( strCrit );

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QString strMethod = "";
        QString strType = "";
        QString strData = "";

        QStringList infoList = info.split("$");

        if( infoList.size() < 3 ) continue;

        strMethod = infoList.at(0);
        strType = infoList.at(1);
        strData = infoList.at(2);

        mAIATable->insertRow(i);
        mAIATable->setRowHeight(i,10);
        mAIATable->setItem( i, 0, new QTableWidgetItem(strMethod));
        mAIATable->setItem( i, 1, new QTableWidgetItem(strType));
        mAIATable->setItem( i, 2, new QTableWidgetItem(strData));
        mAIATable->item( i, 2 )->setToolTip( strData );
    }
}

void ViewCertProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    if( mAKILabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setAKIEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    QString strValue = profileRec.getValue();

    mAKICritLabel->setText( strCrit );
    mAKIText->setText( tr("YES" ) );
    if( strValue.contains( "ISSUER" ))
        mAKIIssuerText->setText( tr("YES") );

    if( strValue.contains( "SERIAL" ))
        mAKISerialText->setText( tr("YES") );
}

void ViewCertProfileDlg::setBCUse( ProfileExtRec& profileRec )
{
    if( mBCLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 3, true );
        setBCEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mBCCritLabel->setText( strCrit );
    QString strVal = profileRec.getValue();
    QStringList valList = strVal.split("#");

    if( valList.size() > 0 )
        mBCTargetText->setText( valList.at(0));

    if( valList.size() > 1 )
        mBCPathLenText->setText( valList.at(1));
}

void ViewCertProfileDlg::setCRLDPUse( ProfileExtRec& profileRec )
{
    if( mCRLDPLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 2, true );
        setCRLDPEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mCRLDPCritLabel->setText( strCrit );

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
        mCRLDPTable->item( i, 1)->setToolTip( strData );
    }

}

void ViewCertProfileDlg::setEKUUse( ProfileExtRec& profileRec )
{
    if( mEKULabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 2, true );
        setEKUEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    QString strValue = profileRec.getValue();
    strValue.replace( "#", "," );

    mEKUCritLabel->setText( strCrit );
    mEKUText->setText( profileRec.getValue() );
}

void ViewCertProfileDlg::setIANUse( ProfileExtRec& profileRec )
{
    if( mIANLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 3, true );
        setIANEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mIANCritLabel->setText( strCrit );

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
        mIANTable->setItem(i, 1, new QTableWidgetItem(strData));
        mIANTable->item(i,1)->setToolTip( strData );
    }
}

void ViewCertProfileDlg::setKeyUsageUse( ProfileExtRec& profileRec )
{
    if( mKeyUsageLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setKeyUsageEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    QString strValue = profileRec.getValue();
    strValue.replace( "#", "," );

    mKeyUsageCritLabel->setText( strCrit );
    mKeyUsageText->setText( strValue );
}

void ViewCertProfileDlg::setNCUse( ProfileExtRec& profileRec )
{
    if( mNCLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 4, true );
        setNCEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mNCCritLabel->setText( strCrit );
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

void ViewCertProfileDlg::setPolicyUse( ProfileExtRec& profileRec )
{
    if( mPolicyLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setPolicyEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mPolicyCritLabel->setText( strCrit );

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

        mPolicyTable->item( row, 0 )->setToolTip( strOID );
        mPolicyTable->item( row, 1 )->setToolTip( strCPS );
        mPolicyTable->item( row, 2 )->setToolTip( strUserNotice );
    }
}

void ViewCertProfileDlg::setPCUse( ProfileExtRec& profileRec )
{
    if( mPCLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 4, true );
        setPCEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mPCCritLabel->setText( strCrit );

    QString strVal = profileRec.getValue();
//    mPCText->setText( strVal );

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        if( infoList.size() < 2 ) continue;

        QString strType = infoList.at(0);
        QString strData = infoList.at(1);

        if( strType == "REP" )
            mPC_REPText->setText( strData );
        else if( strType == "IPM" )
            mPC_IPMText->setText( strData );
    }
}

void ViewCertProfileDlg::setPMUse( ProfileExtRec& profileRec )
{
    if( mPMLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 4, true );
        setPMEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mPMCritLabel->setText( strCrit );

    QString strVal = profileRec.getValue();

    QStringList valList = strVal.split("#");

    for( int i=0; i < valList.size(); i++ )
    {
        QString info = valList.at(i);
        QStringList infoList = info.split("$");

        if( infoList.size() < 2 ) continue;

        QString strIDP = infoList.at(0);
        QString strSDP = infoList.at(1);

        mPMTable->insertRow(i);
        mPMTable->setRowHeight( i, 10 );
        mPMTable->setItem(i,0,new QTableWidgetItem("issuerDomainPolicy"));
        mPMTable->setItem(i,1,new QTableWidgetItem(strIDP));
        mPMTable->setItem(i,2,new QTableWidgetItem("subjectDomainPolicy"));
        mPMTable->setItem(i,3,new QTableWidgetItem(strSDP));

        mPMTable->item( i, 1 )->setToolTip( strIDP );
        mPMTable->item(i, 3)->setToolTip( strSDP );
    }
}

void ViewCertProfileDlg::setSKIUse( ProfileExtRec& profileRec )
{
    if( mSKILabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setSKIEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mSKICritLabel->setText( strCrit );
    mSKIText->setText( tr("YES") );
}

void ViewCertProfileDlg::setSANUse( ProfileExtRec& profileRec )
{
    if( mSANLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 3, true );
        setSANEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mSANCritLabel->setText( strCrit );

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

        mSANTable->item(i,1)->setToolTip( strData );
    }
}

void ViewCertProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{
    if( mExtensionsGroup->isEnabled() == false ) setExtensionsEnable(true);

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

int ViewCertProfileDlg::setProfile( int nNum )
{
    static QStringList kExtUsageList = {
        tr("The Certificate Extension Only"),
        tr("The CSR Extension Only"),
        tr("Both Certificate and CSR and the The certificate first"),
        tr("Both Certificate and CSR and the CSR first")
    };

    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    profile_num_ = nNum;

    CertProfileRec certProfile;



    ret = dbMgr->getCertProfileRec( profile_num_, certProfile );
    if( ret < 0 )
    {
        manApplet->warningBox( tr( "fail to get certificate profile: %1" ).arg( ret ), this );
        return ret;
    }

    mNameText->setText( certProfile.getName() );

    if( certProfile.getType() == JS_PKI_PROFILE_TYPE_CSR )
    {
        mVersionText->setText( "V1" );
        mValidPeriodLabel->setEnabled(false);
        mNotBeforeLabel->setEnabled(false);
        mNotBeforeText->setEnabled(false);
        mNotAfterLabel->setEnabled(false);
        mNotAfterText->setEnabled(false);
        mDNTemplateLabel->setEnabled(false);
        mDNTemplateText->setEnabled(false);
        mExtensionUsageLabel->setEnabled(false);
        mExtensionUsageText->setEnabled(false);

        mTitleLabel->setText( tr( "CSR Profile View" ));
    }
    else
    {
        int nNotBefore = 0;
        int nNotAfter = 0;
        QString strNotBefore;
        QString strNotAfter;

        mVersionText->setText( QString("V%1").arg(certProfile.getVersion() + 1));
        mHashText->setText( certProfile.getHash() );

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

        mDNTemplateText->setText( certProfile.getDNTemplate() );
        mExtensionUsageText->setText( kExtUsageList.at(certProfile.getExtUsage()));
    }

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
