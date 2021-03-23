#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "crl_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_util.h"
#include "commons.h"

CRLInfoDlg::CRLInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    crl_num_ = -1;
    ext_info_list_ = NULL;
    revoke_info_list_ = NULL;

    memset( &crl_info_, 0x00, sizeof(crl_info_));
}

CRLInfoDlg::~CRLInfoDlg()
{

}

void CRLInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CRLInfoDlg::setCRLNum(int crl_num)
{
    crl_num_ = crl_num;
}

void CRLInfoDlg::clickClose()
{
    this->hide();
}

void CRLInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binCRL = {0,0};
    char    sLastUpdate[64];
    char    sNextUpdate[64];

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    tabWidget->setCurrentIndex(0);

    JS_PKI_resetCRLInfo( &crl_info_ );

    if( crl_num_ < 0 )
    {
        manApplet->warningBox( tr("Select CRL"), this );
        return;
    }

    clearTable();
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( revoke_info_list_ ) JS_PKI_resetRevokeInfoList( &revoke_info_list_ );

    CRLRec crl;
    dbMgr->getCRLRec( crl_num_, crl );

    JS_BIN_decodeHex( crl.getCRL().toStdString().c_str(), &binCRL );

    ret = JS_PKI_getCRLInfo( &binCRL, &crl_info_, &ext_info_list_, &revoke_info_list_ );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to get CRL information"), this );
        JS_BIN_reset( &binCRL );
        this->hide();
        return;
    }

    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("Version")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.nVersion)));
    i++;

    if( crl_info_.pIssuerName )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("IssuerName")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pIssuerName)));
        i++;
    }


    JS_UTIL_getDateTime( crl_info_.uLastUpdate, sLastUpdate );
    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("LastUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sLastUpdate)));
    i++;

    JS_UTIL_getDateTime( crl_info_.uNextUpdate, sNextUpdate );
    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("NextUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNextUpdate)));
    i++;

    if( crl_info_.pSignAlgorithm )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("SignAlgorithm")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pSignAlgorithm)));
        i++;
    }

    if( crl_info_.pSignature )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("Signature")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pSignature)));
        i++;
    }

    if( ext_info_list_ )
    {
        JExtensionInfoList *pCurList = ext_info_list_;

        while( pCurList )
        {
            ProfileExtRec profileExt;
            transExtInfoToDBRec( &pCurList->sExtensionInfo, profileExt );
            mCRLListTable->insertRow(i);
            mCRLListTable->setRowHeight(i,10);
            mCRLListTable->setItem(i,0, new QTableWidgetItem(QString("%1").arg(profileExt.getSN())));
            mCRLListTable->setItem(i,1, new QTableWidgetItem(QString("[%1]%2")
                                                               .arg(profileExt.isCritical())
                                                               .arg(profileExt.getValue())));


            pCurList = pCurList->pNext;
            i++;
        }
    }

    if( revoke_info_list_ )
    {
        int k = 0;
        JRevokeInfoList *pCurRevList = revoke_info_list_;

        while( pCurRevList )
        {
            mRevokeListTable->insertRow(k);
            mCRLListTable->setRowHeight(k,10);
            mRevokeListTable->setItem( k, 0, new QTableWidgetItem(QString("%1").arg( pCurRevList->sRevokeInfo.pSerial)));
            mRevokeListTable->setItem( k, 1, new QTableWidgetItem(QString("%1").arg( pCurRevList->sRevokeInfo.uRevokeDate)));

            pCurRevList = pCurRevList->pNext;
            k++;
        }
    }

    JS_BIN_reset( &binCRL );
}

void CRLInfoDlg::initUI()
{
    QStringList sCRLLabels = { tr("Field"), tr("Value") };

    mCRLListTable->clear();
    mCRLListTable->horizontalHeader()->setStretchLastSection(true);
    mCRLListTable->setColumnCount(2);
    mCRLListTable->setHorizontalHeaderLabels( sCRLLabels );
    mCRLListTable->verticalHeader()->setVisible(false);
    mCRLListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QStringList sRevokeLabels = { tr("Serial"), tr("RevokedDate") };
    mRevokeListTable->clear();
    mRevokeListTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeListTable->setColumnCount(2);
    mRevokeListTable->setHorizontalHeaderLabels( sRevokeLabels );
    mRevokeListTable->verticalHeader()->setVisible(false);
    mRevokeListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    mRevokeDetailTable->clear();
    mRevokeDetailTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeDetailTable->setColumnCount(2);
    mRevokeDetailTable->setHorizontalHeaderLabels(sCRLLabels);
    mRevokeDetailTable->verticalHeader()->setVisible(false);
    mRevokeDetailTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeDetailTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeDetailTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mCRLListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickCRLField(QModelIndex)));
    connect( mRevokeListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickRevokeField(QModelIndex)));
}

void CRLInfoDlg::clearTable()
{
    int rowCnt = mCRLListTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mCRLListTable->removeRow(0);

    rowCnt = mRevokeListTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeListTable->removeRow(0);

    rowCnt = mRevokeDetailTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeDetailTable->removeRow(0);
}

void CRLInfoDlg::clickCRLField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mCRLListTable->item( row, 1 );
    if( item == NULL ) return;

    mCRLDetailText->setPlainText( item->text() );
}

void CRLInfoDlg::clickRevokeField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    int rowCnt = mRevokeDetailTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeDetailTable->removeRow(0);

    JRevokeInfoList *pRevInfoList = revoke_info_list_;

    for( int i = 0; i < row; i++ )
    {
        pRevInfoList = pRevInfoList->pNext;
    }

    ProfileExtRec profileExt;

    transExtInfoToDBRec( &pRevInfoList->sRevokeInfo.sExtReason, profileExt );

    mRevokeDetailTable->insertRow(0);
    mRevokeDetailTable->setColumnWidth(0,10);
    mRevokeDetailTable->setItem(0,0, new QTableWidgetItem(QString("%1")
                                                                .arg(profileExt.getSN())));
    mRevokeDetailTable->setItem(0,1, new QTableWidgetItem(QString("[%1]%2")
                                                           .arg(profileExt.isCritical())
                                                           .arg(profileExt.getValue())));
}
