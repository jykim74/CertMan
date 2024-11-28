#include "ca_man_dlg.h"
#include "commons.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "cert_rec.h"
#include "crl_rec.h"
#include "req_rec.h"
#include "key_pair_rec.h"

#include "js_pki_x509.h"

CAManDlg::CAManDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCACertTab->layout()->setSpacing(5);
    mCACertTab->layout()->setMargin(5);
    mCACertGroup->layout()->setSpacing(5);
    mCACertGroup->layout()->setMargin(5);

    mKeyPairTab->layout()->setSpacing(5);
    mKeyPairTab->layout()->setMargin(5);
    mKeyPairGroup->layout()->setSpacing(5);
    mKeyPairGroup->layout()->setMargin(5);

    mCSRTab->layout()->setSpacing(5);
    mCSRTab->layout()->setMargin(5);
    mCSRGroup->layout()->setSpacing(5);
    mCSRGroup->layout()->setMargin(5);
#endif

    initUI();
    mOKBtn->setDefault(true);
    mOKBtn->hide();
    mTabWidget->setCurrentIndex(0);

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CAManDlg::~CAManDlg()
{

}

void CAManDlg::setMode( int nMode )
{
    if( nMode != CAManModeManage )
    {
        mCACertGroup->hide();
        mKeyPairGroup->hide();
        mCSRGroup->hide();

        mOKBtn->show();

        mTabWidget->setTabEnabled( TAB_CA_CERT_IDX, false );
        mTabWidget->setTabEnabled( TAB_KEYPAIR_IDX, false );
        mTabWidget->setTabEnabled( TAB_CSR_IDX, false );
    }

    if( nMode == CAManModeSelectCACert )
    {
        mTabWidget->setCurrentIndex( TAB_CA_CERT_IDX );
        mTabWidget->setTabEnabled( TAB_CA_CERT_IDX, true );
    }
    else if( nMode == CAManModeSelectKeyPair )
    {
        mTabWidget->setCurrentIndex( TAB_KEYPAIR_IDX );
        mTabWidget->setTabEnabled( TAB_KEYPAIR_IDX, true );
    }
    else if( nMode == CAManModeSelectCSR )
    {
        mTabWidget->setCurrentIndex( TAB_CSR_IDX );
        mTabWidget->setTabEnabled( TAB_CSR_IDX, true );
    }
}

void CAManDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void CAManDlg::initUI()
{
#if defined(Q_OS_MAC)
    int nWidth = width() * 9/10;
#else
    int nWidth = width() * 8/10;
#endif

    QStringList sCACertLabels = { tr( "Subject DN" ), tr( "Serial" ), tr( "Algorithm" ) };

    mCACertTable->clear();
    mCACertTable->horizontalHeader()->setStretchLastSection(true);
    mCACertTable->setColumnCount( sCACertLabels.size() );
    mCACertTable->setHorizontalHeaderLabels( sCACertLabels );
    mCACertTable->verticalHeader()->setVisible(false);
    mCACertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCACertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCACertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCACertTable->setColumnWidth( 0, nWidth * 5/10 );
    mCACertTable->setColumnWidth( 1, nWidth * 2/10 );
    mCACertTable->setColumnWidth( 2, nWidth * 3/10 );

    QStringList sKeyPairLabels = { tr( "RegTime" ), tr( "Name" ), tr( "Algorithm" ) };

    mKeyPairTable->clear();
    mKeyPairTable->horizontalHeader()->setStretchLastSection(true);
    mKeyPairTable->setColumnCount( sKeyPairLabels.size() );
    mKeyPairTable->setHorizontalHeaderLabels( sKeyPairLabels );
    mKeyPairTable->verticalHeader()->setVisible(false);
    mKeyPairTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mKeyPairTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mKeyPairTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mKeyPairTable->setColumnWidth( 0, nWidth * 5/10 );
    mKeyPairTable->setColumnWidth( 1, nWidth * 2/10 );
    mKeyPairTable->setColumnWidth( 2, nWidth * 3/10 );

    QStringList sCSRLabels = { tr( "RegTime" ), tr( "Name" ), tr( "Hash" ) };

    mCSRTable->clear();
    mCSRTable->horizontalHeader()->setStretchLastSection(true);
    mCSRTable->setColumnCount( sCSRLabels.size() );
    mCSRTable->setHorizontalHeaderLabels( sCSRLabels );
    mCSRTable->verticalHeader()->setVisible(false);
    mCSRTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCSRTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCSRTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCSRTable->setColumnWidth( 0, nWidth * 5/10 );
    mCSRTable->setColumnWidth( 1, nWidth * 2/10 );
    mCSRTable->setColumnWidth( 2, nWidth * 3/10 );
}

void CAManDlg::initialize()
{
    int index = mTabWidget->currentIndex();

    if( index == TAB_CA_CERT_IDX )
        loadCACertList();
    else if( index == TAB_KEYPAIR_IDX )
        loadKeyPairList();
    else if( index == TAB_CSR_IDX )
        loadCSRList();
}

void CAManDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CAManDlg::changeTab( int index )
{
    if( index == TAB_CA_CERT_IDX )
        loadCACertList();
    else if( index == TAB_KEYPAIR_IDX )
        loadKeyPairList();
    else
        loadCSRList();
}

void CAManDlg::clickOK()
{

}

void CAManDlg::loadCACertList()
{
    int ret = 0;
    DBMgr *dbMgr = manApplet->dbMgr();

    QList<CertRec> certList;

    mCACertTable->setRowCount(0);

    ret = dbMgr->getCACertList( certList );

    for( int i = 0; i < certList.size(); i++ )
    {
        CertRec cert = certList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( cert.getSubjectDN() );

        mCACertTable->insertRow(0);
        mCACertTable->setRowHeight(0, 10);
        mCACertTable->setItem( 0, 0, item );
        mCACertTable->setItem( 0, 1, new QTableWidgetItem( QString("%1").arg( cert.getSerial() )));
        mCACertTable->setItem( 0, 2, new QTableWidgetItem( QString("%1").arg( cert.getSignAlg() )));
    }
}

void CAManDlg::loadKeyPairList()
{
    mKeyPairTable->setRowCount(0);

    QList<KeyPairRec> keyPairList;

    DBMgr *dbMgr = manApplet->dbMgr();

    int ret = dbMgr->getKeyPairList( 0, keyPairList );

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        KeyPairRec keyPair = keyPairList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( keyPair.getName() );

        mKeyPairTable->insertRow(0);
        mKeyPairTable->setRowHeight(0,10);
        mKeyPairTable->setItem( 0, 0, new QTableWidgetItem( QString("%1").arg( keyPair.getRegTime() )));
        mKeyPairTable->setItem( 0, 1, item );
        mKeyPairTable->setItem( 0, 2, new QTableWidgetItem( QString("%1").arg( keyPair.getAlg() )));
    }
}

void CAManDlg::loadCSRList()
{
    mCSRTable->setRowCount(0);

    QList<ReqRec> reqList;

    DBMgr *dbMgr = manApplet->dbMgr();

    int ret = dbMgr->getReqList( 0, reqList );

    for( int i = 0; i < reqList.size(); i++ )
    {
        ReqRec req = reqList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( req.getName() );

        mCSRTable->insertRow(0);
        mCSRTable->setRowHeight(0,10);
        mCSRTable->setItem( 0, 0, new QTableWidgetItem( QString("%1").arg( req.getRegTime() )));
        mCSRTable->setItem( 0, 1, item );
        mCSRTable->setItem( 0, 2, new QTableWidgetItem( QString("%1").arg( req.getHash() )));
    }
}
