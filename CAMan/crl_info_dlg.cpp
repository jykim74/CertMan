#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "crl_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"

CRLInfoDlg::CRLInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    crl_num_ = -1;
}

CRLInfoDlg::~CRLInfoDlg()
{

}

void CRLInfoDlg::setCRLNum(int crl_num)
{
    crl_num_ = crl_num;
}

void CRLInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
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
    JSCRLInfo  sCRLInfo;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    if( crl_num_ < 0 )
    {
        manApplet->warningBox( tr("Select CRL"), this );
        this->hide();
        return;
    }

    clearTable();

    CRLRec crl;
    dbMgr->getCRLRec( crl_num_, crl );

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));
    JS_BIN_decodeHex( crl.getCRL().toStdString().c_str(), &binCRL );

    ret = JS_PKI_getCRLInfo( &binCRL, &sCRLInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to get CRL information"), this );
        JS_BIN_reset( &binCRL );
        this->hide();
        return;
    }

    mCRLListTable->insertRow(i);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("Version")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCRLInfo.nVersion)));
    i++;

    if( sCRLInfo.pIssuerName )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("IssuerName")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCRLInfo.pIssuerName)));
        i++;
    }

    mCRLListTable->insertRow(i);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("LastUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCRLInfo.uLastUpdate)));
    i++;

    mCRLListTable->insertRow(i);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("NextUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCRLInfo.uNextUpdate)));
    i++;

    if( sCRLInfo.pSignAlgorithm )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("SignAlgorithm")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCRLInfo.pSignAlgorithm)));
        i++;
    }

    if( sCRLInfo.pSignature )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( QString("Signature")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCRLInfo.pSignature)));
        i++;
    }

    if( sCRLInfo.pExtList )
    {
        JSExtensionInfoList *pCurList = sCRLInfo.pExtList;

        while( pCurList )
        {
            mCRLListTable->insertRow(i);
            mCRLListTable->setItem(i,0, new QTableWidgetItem(QString("%1").arg(pCurList->sExtensionInfo.pOID)));
            mCRLListTable->setItem(i,1, new QTableWidgetItem(QString("[%1]%2")
                                                               .arg(pCurList->sExtensionInfo.bCritical)
                                                               .arg(pCurList->sExtensionInfo.pValue)));


            pCurList = pCurList->pNext;
            i++;
        }
    }

    JS_BIN_reset( &binCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );
}

void CRLInfoDlg::initUI()
{
    QStringList sCRLLabels = { tr("Field"), tr("Value") };

    mCRLListTable->clear();
    mCRLListTable->horizontalHeader()->setStretchLastSection(true);
    mCRLListTable->setColumnCount(2);
    mCRLListTable->setHorizontalHeaderLabels( sCRLLabels );
    mCRLListTable->verticalHeader()->setVisible(false);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mCRLListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
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

void CRLInfoDlg::clickField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mCRLListTable->item( row, 1 );
    if( item == NULL ) return;

    mCRLDetailText->setPlainText( item->text() );
}
