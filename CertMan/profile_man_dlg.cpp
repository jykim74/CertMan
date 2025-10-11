#include <QMenu>

#include "profile_man_dlg.h"
#include "ca_man_dlg.h"
#include "commons.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "cert_profile_rec.h"
#include "crl_profile_rec.h"
#include "make_cert_profile_dlg.h"
#include "make_crl_profile_dlg.h"
#include "view_cert_profile_dlg.h"
#include "view_crl_profile_dlg.h"

#include "js_pki_x509.h"
#include "js_pki_ext.h"

static const QStringList kCertProfileType = { "Certificate", "CSR" };

ProfileManDlg::ProfileManDlg(QWidget *parent) :
    QDialog(parent)
{
    num_ = -1;

    setupUi(this);
    initUI();
    mTabWidget->setCurrentIndex(0);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));
    connect( mCertTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadCertProfileList()));

    connect( mCertTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotCertTableMenuRequested(QPoint)));
    connect( mCRLTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT( slotCRLTableMenuRequested(QPoint)));

    connect( mCertViewBtn, SIGNAL(clicked()), this, SLOT(clickCertProfileView()));
    connect( mCertDeleteBtn, SIGNAL(clicked()), this, SLOT(clickCertProfileDelete()));

    connect( mCRLViewBtn, SIGNAL(clicked()), this, SLOT(clickCRLProfileView()));
    connect( mCRLDeleteBtn, SIGNAL(clicked()), this, SLOT(clickCRLProfileDelete()));

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


    mOKBtn->setDefault(true);
    mOKBtn->hide();



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

        connect( mCertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mCRLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
    }
    else
    {
        connect( mCertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickCertProfileView()));
        connect( mCRLTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickCRLProfileView()));
    }

    if( nMode == ProfileManModeSelectCertProfile || nMode == ProfileManModeSelectCSRProfile )
    {
        mCertTypeCombo->clear();
        if( nMode == ProfileManModeSelectCertProfile )
        {
            mCertTypeCombo->addItem( "Certificate" );
        }
        else
        {
            mCertTypeCombo->addItem( "CSR" );
        }

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

void ProfileManDlg::slotCertTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewAct = new QAction( tr( "View" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(clickCertProfileView()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickCertProfileDelete()));

    menu->addAction( viewAct );
    menu->addAction( deleteAct );

    menu->popup( mCertTable->viewport()->mapToGlobal(pos));
}

void ProfileManDlg::slotCRLTableMenuRequested( QPoint pos )
{
    QMenu *menu = new QMenu(this);

    QAction *viewAct = new QAction( tr( "View" ), this );
    QAction *deleteAct = new QAction( tr( "Delete" ), this );

    connect( viewAct, SIGNAL(triggered()), this, SLOT(clickCRLProfileView()));
    connect( deleteAct, SIGNAL(triggered()), this, SLOT(clickCRLProfileDelete()));

    menu->addAction( viewAct );
    menu->addAction( deleteAct );

    menu->popup( mCRLTable->viewport()->mapToGlobal(pos));
}

void ProfileManDlg::clickOK()
{
    num_ = -1;

    QModelIndex idx;
    QTableWidgetItem *item = NULL;
    int nTabIdx = mTabWidget->currentIndex();

    if( nTabIdx == 0 )
    {
        idx = mCertTable->currentIndex();
        item = mCertTable->item( idx.row(), 0 );
    }
    else if( nTabIdx == 1 )
    {
        idx = mCRLTable->currentIndex();
        item = mCRLTable->item( idx.row(), 0 );
    }

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    num_ = item->data(Qt::UserRole).toInt();

    accept();
}

void ProfileManDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 9/10;
#else
    int nWidth = width() * 8/10;
#endif
    mCertTypeCombo->addItems( kCertProfileType );

    QStringList sCertLabels = { tr( "Num" ), tr( "NotBefore" ), tr( "NotAfter" ), tr( "Name") };

    mCertTable->clear();
    mCertTable->horizontalHeader()->setStretchLastSection(true);
    mCertTable->setColumnCount( sCertLabels.size() );
    mCertTable->setHorizontalHeaderLabels( sCertLabels );
    mCertTable->verticalHeader()->setVisible(false);
    mCertTable->setStyleSheet( kSelectStyle );
    mCertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCertTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mCertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCertTable->setColumnWidth( 0, 60 );
    mCertTable->setColumnWidth( 1, 100 );
    mCertTable->setColumnWidth( 2, 100 );

    QStringList sCRLLabels = { tr( "Num"), tr( "ThisUpdate" ), tr( "NextUpdate" ), tr( "Name") };

    mCRLTable->clear();
    mCRLTable->horizontalHeader()->setStretchLastSection(true);
    mCRLTable->setColumnCount( sCRLLabels.size() );
    mCRLTable->setHorizontalHeaderLabels( sCRLLabels );
    mCRLTable->verticalHeader()->setVisible(false);
    mCRLTable->setStyleSheet( kSelectStyle );
    mCRLTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mCRLTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCRLTable->setColumnWidth( 0, 60 );
    mCRLTable->setColumnWidth( 1, 100 );
    mCRLTable->setColumnWidth( 2, 100 );
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

    QString strType = mCertTypeCombo->currentText();

    int ret = 0;
    if( strType == "Certificate" )
        ret = dbMgr->getCertProfileListByType( JS_PKI_PROFILE_TYPE_CERT, profileList );
    else
        ret = dbMgr->getCertProfileListByType( JS_PKI_PROFILE_TYPE_CSR, profileList );

    mCertTable->setRowCount(0);

    for( int i = 0; i < profileList.size(); i++ )
    {
        QString strNotBefore;
        QString strNotAfter;

        CertProfileRec profile = profileList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( QString("%1").arg( profile.getNum() ));
        item->setData(Qt::UserRole, profile.getNum() );

        if( profile.getType() == JS_PKI_PROFILE_TYPE_CSR )
            item->setIcon(QIcon(":/images/csr_profile.png"));
        else
            item->setIcon(QIcon(":/images/cert_profile.png"));

        getPeriodString( profile.getNotBefore(), profile.getNotAfter(), strNotBefore, strNotAfter );

        mCertTable->insertRow(i);
        mCertTable->setRowHeight(i, 10);
        mCertTable->setItem( i, 0, item );
        mCertTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg( strNotBefore )));
        mCertTable->setItem( i, 2, new QTableWidgetItem(QString("%1").arg( strNotAfter )));
        mCertTable->setItem( i, 3, new QTableWidgetItem(QString("%1").arg( profile.getName())) );
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
        QString strThisUpdate;
        QString strNextUpdate;

        CRLProfileRec profile = profileList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( QString("%1").arg( profile.getNum()) );
        item->setData(Qt::UserRole, profile.getNum() );
        item->setIcon(QIcon(":/images/crl_profile.png"));

        getPeriodString( profile.getThisUpdate(), profile.getNextUpdate(), strThisUpdate, strNextUpdate );

        mCRLTable->insertRow(i);
        mCRLTable->setRowHeight(0, 10);
        mCRLTable->setItem( i, 0, item );
        mCRLTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg( strThisUpdate )));
        mCRLTable->setItem( i, 2, new QTableWidgetItem(QString("%1").arg( strNextUpdate )));
        mCRLTable->setItem( i, 3, new QTableWidgetItem(QString("%1").arg( profile.getName() )) );
    }
}

void ProfileManDlg::clickCertProfileView()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
/*
    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.setEdit(num);
    makeCertProfileDlg.setReadOnly();
    makeCertProfileDlg.exec();
*/
    ViewCertProfileDlg certProfile;
    certProfile.setProfile( num );
    certProfile.exec();
}

void ProfileManDlg::clickCertProfileDelete()
{
    QModelIndex idx = mCertTable->currentIndex();
    QTableWidgetItem *item = mCertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the certificate profile?" ), this, false );
    if( bVal == false ) return;

    int ret = manApplet->dbMgr()->delCertProfile(num);
    if( ret == 0 ) loadCertProfileList();
}

void ProfileManDlg::clickCRLProfileView()
{
    QModelIndex idx = mCRLTable->currentIndex();
    QTableWidgetItem *item = mCRLTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();

    /*
    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.setEdit(num);
    makeCRLProfileDlg.setReadOnly();
    makeCRLProfileDlg.exec();
    */
    ViewCRLProfileDlg crlProfile;
    crlProfile.setProfile( num );
    crlProfile.exec();
}

void ProfileManDlg::clickCRLProfileDelete()
{
    QModelIndex idx = mCRLTable->currentIndex();
    QTableWidgetItem *item = mCRLTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the CRL profile?" ), this, false );
    if( bVal == false ) return;

    int ret = manApplet->dbMgr()->delCertProfile(num);
    if( ret == 0 ) loadCRLProfileList();
}
