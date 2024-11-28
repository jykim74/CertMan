#include "profile_man_dlg.h"
#include "ca_man_dlg.h"
#include "commons.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "cert_profile_rec.h"
#include "crl_profile_rec.h"

#include "js_pki_x509.h"

ProfileManDlg::ProfileManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCertTab->layout()->setSpacing(5);
    mCertTab->layout()->setMargin(5);
    mCertGroup->layout()->setSpacing(5);
    mCertGroup->layout()->setMargin(5);

    mCRLTab->layout()->setSpacing(5);
    mCRLTab->layout()->setMargin(5);
    mCRLGroup->layout()->setSpacing(5);
    mCRLGroup->layout()->setMargin(5);
#endif

    initUI();
    mOKBtn->setDefault(true);
    mOKBtn->hide();

    mTabWidget->setCurrentIndex(0);

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ProfileManDlg::~ProfileManDlg()
{

}

void ProfileManDlg::setMode( int nMode )
{
    if( nMode != ProfileManModeManage )
    {
        mCertGroup->hide();
        mCRLGroup->hide();

        mOKBtn->show();

        mTabWidget->setTabEnabled( 0, false );
        mTabWidget->setTabEnabled( 1, false );
    }

    if( nMode == ProfileManModeSelectCertProfile )
    {
        mTabWidget->setCurrentIndex(0);
        mTabWidget->setTabEnabled(0, true);
    }
    else if( nMode == ProfileManModeSelectCRLProfile )
    {
        mTabWidget->setCurrentIndex(1);
        mTabWidget->setTabEnabled(1, true);
    }
}

void ProfileManDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void ProfileManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void ProfileManDlg::changeTab( int index )
{
    if( index == 0 )
        loadCertProfileList();
    else
        loadCRLProfileList();
}

void ProfileManDlg::clickOK()
{

}

void ProfileManDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 9/10;
#else
    int nWidth = width() * 8/10;
#endif

    QStringList sCertLabels = { tr( "Name" ), tr( "NotBefore" ), tr( "NotAfter" ) };

    mCertTable->clear();
    mCertTable->horizontalHeader()->setStretchLastSection(true);
    mCertTable->setColumnCount( sCertLabels.size() );
    mCertTable->setHorizontalHeaderLabels( sCertLabels );
    mCertTable->verticalHeader()->setVisible(false);
    mCertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCertTable->setColumnWidth( 0, nWidth * 5/10 );
    mCertTable->setColumnWidth( 1, nWidth * 2/10 );
    mCertTable->setColumnWidth( 2, nWidth * 3/10 );

    QStringList sCRLLabels = { tr( "Name" ), tr( "ThisUpdate" ), tr( "NextUpdate" ) };

    mCRLTable->clear();
    mCRLTable->horizontalHeader()->setStretchLastSection(true);
    mCRLTable->setColumnCount( sCRLLabels.size() );
    mCRLTable->setHorizontalHeaderLabels( sCRLLabels );
    mCRLTable->verticalHeader()->setVisible(false);
    mCRLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCRLTable->setColumnWidth( 0, nWidth * 5/10 );
    mCRLTable->setColumnWidth( 1, nWidth * 2/10 );
    mCRLTable->setColumnWidth( 2, nWidth * 3/10 );
}

void ProfileManDlg::initialize()
{
    int index = mTabWidget->currentIndex();

    if( index == 0 )
        loadCertProfileList();
    else
        loadCRLProfileList();
}

void ProfileManDlg::loadCertProfileList()
{
    DBMgr *dbMgr = manApplet->dbMgr();
    QList<CertProfileRec> profileList;

    int ret = dbMgr->getCertProfileList( profileList );

    mCertTable->setRowCount(0);

    for( int i = 0; i < profileList.size(); i++ )
    {
        CertProfileRec profile = profileList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( profile.getName() );

        mCertTable->insertRow(0);
        mCertTable->setRowHeight(0, 10);
        mCertTable->setItem( 0, 0, item );
        mCertTable->setItem( 0, 1, new QTableWidgetItem(QString("%1").arg( profile.getNotBefore() )));
        mCertTable->setItem( 0, 2, new QTableWidgetItem(QString("%1").arg( profile.getNotAfter() )));
    }
}

void ProfileManDlg::loadCRLProfileList()
{
    DBMgr *dbMgr = manApplet->dbMgr();
    QList<CRLProfileRec> profileList;

    int ret = dbMgr->getCRLProfileList( profileList );

    mCRLTable->setRowCount(0);

    for( int i = 0; i < profileList.size(); i++ )
    {
        CRLProfileRec profile = profileList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( profile.getName() );

        mCRLTable->insertRow(0);
        mCRLTable->setRowHeight(0, 10);
        mCRLTable->setItem( 0, 0, item );
        mCRLTable->setItem( 0, 1, new QTableWidgetItem(QString("%1").arg( profile.getThisUpdate() )));
        mCRLTable->setItem( 0, 2, new QTableWidgetItem(QString("%1").arg( profile.getNextUpdate() )));
    }
}
