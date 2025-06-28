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

void ViewCRLProfileDlg::initialize()
{

}

void ViewCRLProfileDlg::setCRLNumUse( ProfileExtRec& profileRec )
{
    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mCRLNumCritLabel->setText( strCrit );

    mCRLNumText->setText( profileRec.getValue() );
}

void ViewCRLProfileDlg::setAKIUse( ProfileExtRec& profileRec )
{
    QString strCrit = tr("NonCritical" );
    if( profileRec.isCritical() == true )
        strCrit = tr( "Critical" );

    mAKICritLabel->setText( strCrit );
    mAKIText->setText( profileRec.getValue() );
}

void ViewCRLProfileDlg::setIDPUse( ProfileExtRec& profileRec )
{
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
    }
}

void ViewCRLProfileDlg::setIANUse( ProfileExtRec& profileRec )
{
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
    }
}

void ViewCRLProfileDlg::setExtensionsUse( ProfileExtRec& profileRec )
{

}

int ViewCRLProfileDlg::setProfile( int nNum )
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return -1;

    profile_num_ = nNum;

    CRLProfileRec crlProfile;

    int nThisUpdate = 0;
    int nNextUpdate = 0;
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
    nThisUpdate = crlProfile.getThisUpdate();
    nNextUpdate = crlProfile.getNextUpdate();

    if( nThisUpdate == 0 )
    {
        strThisUpdate = tr("Creation time");
        strNextUpdate = tr( "%1 Days" ).arg( nNextUpdate );
    }
    else if( nThisUpdate == 1 )
    {
        strThisUpdate = tr("Creation time");
        strNextUpdate = tr( "%1 Months" ).arg( nNextUpdate );
    }
    else if( nThisUpdate == 2 )
    {
        strThisUpdate = tr("Creation time");
        strNextUpdate = tr( "%1 Years" ).arg( nNextUpdate );
    }
    else
    {
        QDateTime thisUpdate;
        QDateTime nextUpdate;
        thisUpdate.setSecsSinceEpoch( nThisUpdate );
        nextUpdate.setSecsSinceEpoch( nNextUpdate );

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
