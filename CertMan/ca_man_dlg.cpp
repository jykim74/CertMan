#include "ca_man_dlg.h"
#include "commons.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "cert_rec.h"
#include "crl_rec.h"
#include "req_rec.h"
#include "key_pair_rec.h"

#include "cert_info_dlg.h"
#include "pri_key_info_dlg.h"
#include "csr_info_dlg.h"

#include "js_pki_x509.h"

static QStringList kKeyAlgList = { "Any", kMechRSA, kMechEC, kMechDSA, kMechEdDSA };
static QStringList kStatus = { "NotUsed", "Used" };

CAManDlg::CAManDlg(QWidget *parent) :
    QDialog(parent)
{
    num_ = -1;

    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mTabWidget, SIGNAL(currentChanged(int)), this, SLOT(changeTab(int)));



    connect( mKeyPairStatusCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadKeyPairList()));
    connect( mCSRStatusCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadCSRList()));

    connect( mCACertTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadCACertList()));
    connect( mKeyPairTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadKeyPairList()));
    connect( mCSRTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(loadCSRList()));

    connect( mCACertViewBtn, SIGNAL(clicked()), this, SLOT(clickCACertView()));
    connect( mCACertDeleteBtn, SIGNAL(clicked()), this, SLOT(clickCACertDelete()));

    connect( mKeyPairViewBtn, SIGNAL(clicked()), this, SLOT(clickKeyPairView()));
    connect( mKeyPairDeleteBtn, SIGNAL(clicked()), this, SLOT(clickKeyPairDelete()));

    connect( mCSRViewBtn, SIGNAL(clicked()), this, SLOT(clickCSRView()));
    connect( mCSRDeleteBtn, SIGNAL(clicked()), this, SLOT(clickCSRDelete()));

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

        connect( mCACertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mKeyPairTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
        connect( mCSRTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickOK()));
    }
    else
    {
        connect( mCACertTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickCACertView()));
        connect( mKeyPairTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickKeyPairView()));
        connect( mCSRTable, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(clickCSRView()));
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

    QStringList sCACertLabels = { tr( "Num"), tr( "Serial" ), tr( "Algorithm" ), tr( "Subject DN" )  };

    mCACertTable->clear();
    mCACertTable->horizontalHeader()->setStretchLastSection(true);
    mCACertTable->setColumnCount( sCACertLabels.size() );
    mCACertTable->setHorizontalHeaderLabels( sCACertLabels );
    mCACertTable->verticalHeader()->setVisible(false);
    mCACertTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCACertTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCACertTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCACertTable->setColumnWidth( 0, 60 );
    mCACertTable->setColumnWidth( 1, 80 );
    mCACertTable->setColumnWidth( 2, 80 );

    QStringList sKeyPairLabels = { tr("Num"), tr("RegTime"), tr( "Algorithm" ), tr( "Name" ) };

    mKeyPairTable->clear();
    mKeyPairTable->horizontalHeader()->setStretchLastSection(true);
    mKeyPairTable->setColumnCount( sKeyPairLabels.size() );
    mKeyPairTable->setHorizontalHeaderLabels( sKeyPairLabels );
    mKeyPairTable->verticalHeader()->setVisible(false);
    mKeyPairTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mKeyPairTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mKeyPairTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mKeyPairTable->setColumnWidth( 0, 60 );
    mKeyPairTable->setColumnWidth( 1, 80 );
    mKeyPairTable->setColumnWidth( 2, 80 );

    QStringList sCSRLabels = { tr( "Num" ), tr("RegTime"), tr( "Subject DN" ), tr( "Name" ) };

    mCSRTable->clear();
    mCSRTable->horizontalHeader()->setStretchLastSection(true);
    mCSRTable->setColumnCount( sCSRLabels.size() );
    mCSRTable->setHorizontalHeaderLabels( sCSRLabels );
    mCSRTable->verticalHeader()->setVisible(false);
    mCSRTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCSRTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCSRTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCSRTable->setColumnWidth( 0, 60 );
    mCSRTable->setColumnWidth( 1, 80 );
    mCSRTable->setColumnWidth( 2, 120 );

    mKeyPairStatusCombo->addItems( kStatus );
    mCSRStatusCombo->addItems( kStatus);

    mCACertTypeCombo->addItems( kKeyAlgList );
    mKeyPairTypeCombo->addItems( kKeyAlgList );
    mCSRTypeCombo->addItems( kKeyAlgList );
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
    num_ = -1;

    QModelIndex idx;
    QTableWidgetItem *item = NULL;
    int nTabIdx = mTabWidget->currentIndex();

    if( nTabIdx == TAB_CA_CERT_IDX )
    {
        idx = mCACertTable->currentIndex();
        item = mCACertTable->item( idx.row(), 0 );
    }
    else if( nTabIdx == TAB_KEYPAIR_IDX )
    {
        idx = mKeyPairTable->currentIndex();
        item = mKeyPairTable->item( idx.row(), 0 );
    }
    else if( nTabIdx == TAB_CSR_IDX )
    {
        idx = mCSRTable->currentIndex();
        item = mCSRTable->item( idx.row(), 0 );
    }

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    num_ = item->data(Qt::UserRole).toInt();

    accept();
}

void CAManDlg::loadCACertList()
{
    int ret = 0;
    DBMgr *dbMgr = manApplet->dbMgr();

    QList<CertRec> certList;
    QString strType = mCACertTypeCombo->currentText();

    mCACertTable->setRowCount(0);

    ret = dbMgr->getCACertList( certList );

    for( int i = 0; i < certList.size(); i++ )
    {
        CertRec cert = certList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( QString("%1").arg( cert.getNum() ) );
        item->setData(Qt::UserRole, cert.getNum() );

        if( strType != "Any" )
        {
            BIN binCert = {0,0};
            int nKeyType = -1;
            JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );
            nKeyType = JS_PKI_getCertKeyType( &binCert );
            JS_BIN_reset( &binCert );

            if( strType == kMechRSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
            }
            else if( strType == kMechEC )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 ) continue;
            }
            else if( strType == kMechDSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
            }
            else if( strType == kMechEdDSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_ED25519 && nKeyType != JS_PKI_KEY_TYPE_ED448 ) continue;
            }
        }

        mCACertTable->insertRow(0);
        mCACertTable->setRowHeight(0, 10);
        mCACertTable->setItem( 0, 0, item );
        mCACertTable->setItem( 0, 1, new QTableWidgetItem( QString("%1").arg( cert.getSerial() )));
        mCACertTable->setItem( 0, 2, new QTableWidgetItem( QString("%1").arg( cert.getSignAlg() )));
        mCACertTable->setItem( 0, 3, new QTableWidgetItem( QString("%1").arg( cert.getSubjectDN())) );
    }
}

void CAManDlg::loadKeyPairList()
{
    mKeyPairTable->setRowCount(0);

    QList<KeyPairRec> keyPairList;
    QString strType = mKeyPairTypeCombo->currentText();

    DBMgr *dbMgr = manApplet->dbMgr();
    int nStatus = mKeyPairStatusCombo->currentIndex();

    int ret = dbMgr->getKeyPairList( nStatus, keyPairList );

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        KeyPairRec keyPair = keyPairList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( QString("%1").arg( keyPair.getNum() ) );
        item->setData(Qt::UserRole, keyPair.getNum() );

        if( strType != "Any" )
        {
            BIN binPub = {0,0};
            int nKeyType = -1;
            JS_BIN_decodeHex( keyPair.getPublicKey().toStdString().c_str(), &binPub );
            nKeyType = JS_PKI_getPubKeyType( &binPub );
            JS_BIN_reset( &binPub );

            if( strType == kMechRSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
            }
            else if( strType == kMechEC )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 ) continue;
            }
            else if( strType == kMechDSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
            }
            else if( strType == kMechEdDSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_ED25519 && nKeyType != JS_PKI_KEY_TYPE_ED448 ) continue;
            }
        }


        mKeyPairTable->insertRow(0);
        mKeyPairTable->setRowHeight(0,10);
        mKeyPairTable->setItem( 0, 0, item );
        mKeyPairTable->setItem( 0, 1, new QTableWidgetItem( QString("%1").arg( dateString( keyPair.getRegTime() ) )));
        mKeyPairTable->setItem( 0, 2, new QTableWidgetItem( QString("%1").arg( keyPair.getAlg() )));
        mKeyPairTable->setItem( 0, 3, new QTableWidgetItem( QString("%1").arg( keyPair.getName())) );
    }
}

void CAManDlg::loadCSRList()
{
    mCSRTable->setRowCount(0);

    QList<ReqRec> reqList;

    QString strType = mCSRTypeCombo->currentText();
    DBMgr *dbMgr = manApplet->dbMgr();
    int nStatus = mCSRStatusCombo->currentIndex();

    int ret = dbMgr->getReqList( nStatus, reqList );

    for( int i = 0; i < reqList.size(); i++ )
    {
        ReqRec req = reqList.at(i);
        QTableWidgetItem *item = new QTableWidgetItem( QString( "%1").arg( req.getSeq() ) );
        item->setData(Qt::UserRole, req.getSeq() );

        if( strType != "Any" )
        {
            BIN binCSR = {0,0};
            int nKeyType = -1;
            JS_BIN_decodeHex( req.getCSR().toStdString().c_str(), &binCSR );
            nKeyType = JS_PKI_getCSRKeyType( &binCSR );
            JS_BIN_reset( &binCSR );

            if( strType == kMechRSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_RSA ) continue;
            }
            else if( strType == kMechEC )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_ECC && nKeyType != JS_PKI_KEY_TYPE_SM2 ) continue;
            }
            else if( strType == kMechDSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_DSA ) continue;
            }
            else if( strType == kMechEdDSA )
            {
                if( nKeyType != JS_PKI_KEY_TYPE_ED25519 && nKeyType != JS_PKI_KEY_TYPE_ED448 ) continue;
            }
        }

        mCSRTable->insertRow(0);
        mCSRTable->setRowHeight(0,10);
        mCSRTable->setItem( 0, 0, item );
        mCSRTable->setItem( 0, 1, new QTableWidgetItem( QString("%1").arg( dateString( req.getRegTime() ) )));
        mCSRTable->setItem( 0, 2, new QTableWidgetItem( QString("%1").arg( req.getDN() )));
        mCSRTable->setItem( 0, 3, new QTableWidgetItem( QString("%1").arg( req.getName())) );
    }
}

void CAManDlg::clickCACertView()
{
    QModelIndex idx = mCACertTable->currentIndex();
    QTableWidgetItem *item = mCACertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    CertRec cert;
    int ret = manApplet->dbMgr()->getCertRec( num, cert );
    if( ret != 0 ) return;

    CertInfoDlg certInfo;
    certInfo.setCertNum( num );
    certInfo.exec();
}

void CAManDlg::clickCACertDelete()
{
    QModelIndex idx = mCACertTable->currentIndex();
    QTableWidgetItem *item = mCACertTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete CA certificate?" ), this, false );
    if( bVal == false ) return;

    int ret = manApplet->dbMgr()->delCertRec( num );
    if( ret == 0 ) loadCACertList();
}

void CAManDlg::clickKeyPairView()
{
    QModelIndex idx = mKeyPairTable->currentIndex();
    QTableWidgetItem *item = mKeyPairTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();

    PriKeyInfoDlg priKeyInfo;
    priKeyInfo.setKeyNum( num );
    priKeyInfo.exec();
}

void CAManDlg::clickKeyPairDelete()
{
    QModelIndex idx = mKeyPairTable->currentIndex();
    QTableWidgetItem *item = mKeyPairTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the keypair?" ), this, false );
    if( bVal == false ) return;

    int ret = manApplet->dbMgr()->delKeyPairRec( num );
    if( ret == 0 ) loadKeyPairList();
}

void CAManDlg::clickCSRView()
{
    QModelIndex idx = mCSRTable->currentIndex();
    QTableWidgetItem *item = mCSRTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    CSRInfoDlg csrInfo;
    csrInfo.setCSRNum(num);
    csrInfo.exec();
}

void CAManDlg::clickCSRDelete()
{
    QModelIndex idx = mCSRTable->currentIndex();
    QTableWidgetItem *item = mCSRTable->item( idx.row(), 0 );

    if( item == NULL )
    {
        manApplet->warningBox( tr( "There are no selected items"), this );
        return;
    }

    int num = item->data(Qt::UserRole).toInt();
    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete the CSR?" ), this, false );
    if( bVal == false ) return;

    int ret = manApplet->dbMgr()->delReqRec( num );
    if( ret == 0 ) loadCSRList();
}
