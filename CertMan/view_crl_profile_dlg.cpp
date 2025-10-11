#include "view_crl_profile_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "settings_mgr.h"
#include "commons.h"

#include "js_gen.h"
#include "js_pki_ext.h"

ViewCRLProfileDlg::ViewCRLProfileDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mProfileToolBox->layout()->setSpacing(5);
    mProfileToolBox->layout()->setMargin(5);

    mBase->layout()->setSpacing(5);
    mBase->layout()->setMargin(5);

    mExtension->layout()->setMargin(5);
    mExtension->layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
    mProfileToolBox->setCurrentIndex(0);

    mCloseBtn->setFocus();
}

ViewCRLProfileDlg::~ViewCRLProfileDlg()
{

}

void ViewCRLProfileDlg::initUI()
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

    QStringList sExtensionsLabels = { tr("OID"), tr("Crit"), tr("Value") };
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

    mProfileToolBox->setItemIcon( 0, QIcon( ":/images/crl_profile.png" ));
    mProfileToolBox->setItemIcon( 1, QIcon( ":/images/crl_profile.png" ));

    setAllEnable( false );
}

void ViewCRLProfileDlg::initialize()
{

}

void ViewCRLProfileDlg::setCRLNumEnable( bool bVal )
{
    mCRLNumCritLabel->setEnabled( bVal );
    mCRLNumLabel->setEnabled( bVal );
    mCRLPeriodLabel->setEnabled(bVal);
}

void ViewCRLProfileDlg::setAKIEnable(bool bVal )
{
    mAKICritLabel->setEnabled(bVal);
    mAKIIssuerLabel->setEnabled(bVal);
    mAKIIssuerText->setEnabled(bVal);
    mAKILabel->setEnabled(bVal);
    mAKISerialLabel->setEnabled(bVal);
    mAKISerialText->setEnabled(bVal);
}

void ViewCRLProfileDlg::setIDPEnable( bool bVal )
{
    mIDPCritLabel->setEnabled(bVal);
    mIDPLabel->setEnabled(bVal);
    mIDPTable->setEnabled(bVal);
}

void ViewCRLProfileDlg::setIANEnable( bool bVal )
{
    mIANCritLabel->setEnabled(bVal);
    mIANLabel->setEnabled(bVal);
    mIANTable->setEnabled(bVal);
}

void ViewCRLProfileDlg::setExtensionsEnable( bool bVal )
{
    if( bVal == false )
        mExtensionsGroup->hide();
    else
        mExtensionsGroup->show();

    mExtensionsGroup->setEnabled( bVal );
}

void ViewCRLProfileDlg::setAllEnable( bool bVal )
{
    setCRLNumEnable( bVal );
    setAKIEnable( bVal );
    setIDPEnable( bVal );
    setIANEnable( bVal );
    setExtensionsEnable( bVal );
}

void ViewCRLProfileDlg::setCRLNumUse( ProfileExtRec& profileRec )
{
    if( mCRLNumLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setCRLNumEnable( true );
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mCRLNumCritLabel->setText( strCrit );

    mCRLNumText->setText( profileRec.getValue() );
}

void ViewCRLProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    if( mAKILabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setAKIEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mAKICritLabel->setText( strCrit );

    QString strValue = profileRec.getValue();

    mAKIText->setText( tr("YES" ) );
    if( strValue.contains( "ISSUER" ))
        mAKIIssuerText->setText( tr("YES") );

    if( strValue.contains( "SERIAL" ))
        mAKISerialText->setText( tr("YES") );

    mAKIText->setText( tr("YES") );
}

void ViewCRLProfileDlg::setIDPUse( ProfileExtRec& profileRec )
{
    if( mIDPLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
        setIDPEnable(true);
    }

    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mIDPCritLabel->setText( strCrit );

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
        mIDPTable->item(i,1)->setToolTip( strData );
    }
}

void ViewCRLProfileDlg::setIANUse( ProfileExtRec& profileRec )
{
    if( mIANLabel->isEnabled() == false )
    {
        mProfileToolBox->setItemEnabled( 1, true );
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
        mIANTable->setItem( i, 1, new QTableWidgetItem(strData));
        mIANTable->item(i,1)->setToolTip( strData );
    }
}

void ViewCRLProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{
    if( mExtensionsGroup->isEnabled() == false ) setExtensionsEnable(true);

    QString strOID = profileRec.getSN();
    QString strValue = profileRec.getValue();
    QString strCrit;

    if( profileRec.isCritical() )
        strCrit = kTrue;
    else
        strCrit = kFalse;

    int row = mExtensionsTable->rowCount();
    mExtensionsTable->setRowCount( row + 1 );
    mExtensionsTable->setRowHeight( row, 10 );
    mExtensionsTable->setItem( row, 0, new QTableWidgetItem(strOID));
    mExtensionsTable->setItem( row, 1, new QTableWidgetItem(strCrit));
    mExtensionsTable->setItem( row, 2, new QTableWidgetItem(strValue));
}

int ViewCRLProfileDlg::setProfile( int nNum )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    profile_num_ = nNum;

    CRLProfileRec crlProfile;

    time_t tThisUpdate = 0;
    time_t tNextUpdate = 0;
    QString strThisUpdate;
    QString strNextUpdate;

    ret = dbMgr->getCRLProfileRec( profile_num_, crlProfile );
    if( ret < 0 )
    {
        manApplet->warningBox( tr( "fail to get CRL profile: %1" ).arg( ret ), this );
        return ret;
    }

    mNameText->setText( crlProfile.getName() );
    mVersionText->setText( QString("V%1").arg( crlProfile.getVersion() + 1));
    mHashText->setText( crlProfile.getHash() );

    tThisUpdate = crlProfile.getThisUpdate();
    tNextUpdate = crlProfile.getNextUpdate();

    if( tThisUpdate == 0 )
    {
        strThisUpdate = tr("Creation time");
        strNextUpdate = tr( "%1 Days" ).arg( tNextUpdate );
    }
    else if( tThisUpdate == 1 )
    {
        strThisUpdate = tr("Creation time");
        strNextUpdate = tr( "%1 Months" ).arg( tNextUpdate );
    }
    else if( tThisUpdate == 2 )
    {
        strThisUpdate = tr("Creation time");
        strNextUpdate = tr( "%1 Years" ).arg( tNextUpdate );
    }
    else
    {
        QDateTime thisUpdate;
        QDateTime nextUpdate;
        thisUpdate.setSecsSinceEpoch( tThisUpdate );
        nextUpdate.setSecsSinceEpoch( tNextUpdate );

        strThisUpdate = thisUpdate.toString( "yyyy-MM-dd hh:mm:ss" );
        strNextUpdate = nextUpdate.toString( "yyyy-MM-dd hh:mm:ss" );
    }

    mThisUpdateText->setText( strThisUpdate );
    mNextUpdateText->setText( strNextUpdate );

    QList<ProfileExtRec> extProfileList;
    dbMgr->getCRLProfileExtensionList( profile_num_, extProfileList );

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

    return 0;
}
