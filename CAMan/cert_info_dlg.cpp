#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_util.h"
#include "commons.h"


CertInfoDlg::CertInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    cert_num_ = -1;
    tabWidget->setCurrentIndex(0);
}

CertInfoDlg::~CertInfoDlg()
{

}

void CertInfoDlg::setCertNum(int cert_num)
{
    cert_num_ = cert_num;
}

void CertInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
    pathInit();
}

void CertInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binCert = {0,0};
    JCertInfo  sCertInfo;
    JExtensionInfoList *pExtInfoList = NULL;
    char    sNotBefore[64];
    char    sNotAfter[64];

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( cert_num_ < 0 )
    {
        manApplet->warningBox( tr( "Select certificate"), this );
        this->hide();
        return;
    }

    clearTable();

    CertRec cert;
    dbMgr->getCertRec( cert_num_, cert );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, &pExtInfoList );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to get certificate information"), this );
        JS_BIN_reset( &binCert );
        this->hide();
        return;
    }

    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( QString("Version")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.nVersion)));
    i++;

    if( sCertInfo.pSerial )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(QString("Serial")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSerial)));
        i++;
    }

    JS_UTIL_getDateTime( sCertInfo.uNotBefore, sNotBefore );
    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( QString("NotBefore")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotBefore)));
    i++;

    JS_UTIL_getDateTime( sCertInfo.uNotAfter, sNotAfter );
    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( QString("NotAfter")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNotAfter)));
    i++;

    if( sCertInfo.pSubjectName )
    {
        QString name = QString::fromUtf8( sCertInfo.pSubjectName );

        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(QString("SubjectName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
        i++;
    }

    if( sCertInfo.pPublicKey )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(QString("PublicKey")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pPublicKey)));
        i++;
    }

    if( sCertInfo.pIssuerName )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(QString("IssuerName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pIssuerName)));
        i++;
    }

    if( sCertInfo.pSignAlgorithm )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(QString("SigAlgorithm")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignAlgorithm)));
        i++;
    }

    if( sCertInfo.pSignature )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(QString("Signature")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignature)));
        i++;
    }

    if( pExtInfoList )
    {
        JExtensionInfoList *pCurList = pExtInfoList;

        while( pCurList )
        {
            ProfileExtRec profileRec;
            transExtInfoToDBRec( &pCurList->sExtensionInfo, profileRec );

            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);
            mFieldTable->setItem(i,0, new QTableWidgetItem(QString("%1").arg(profileRec.getSN())));
            mFieldTable->setItem(i,1, new QTableWidgetItem(QString("[%1]%2")
                                                               .arg(profileRec.isCritical())
                                                               .arg(profileRec.getValue())));


            pCurList = pCurList->pNext;
            i++;
        }
    }

    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
}

void CertInfoDlg::pathInit()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec cert;

    dbMgr->getCertRec( cert_num_, cert );
    cert_list_.push_front( cert );

    int nIssueNum = cert.getIssuerNum();

    while ( nIssueNum > 0 )
    {
        CertRec parent;
        dbMgr->getCertRec( nIssueNum, parent );
        cert_list_.push_front( parent );

        nIssueNum = parent.getIssuerNum();
    }

    mCertPathTree->clear();
    mCertPathTree->header()->setVisible(false);
    mCertPathTree->setColumnCount(1);

    QList<QTreeWidgetItem *> items;
    QTreeWidgetItem* pPrevItem = NULL;

    for( int i=0; i < cert_list_.size(); i++ )
    {
        CertRec cert = cert_list_.at(i);
        QTreeWidgetItem *item = new QTreeWidgetItem( 0 );
        item->setText( 0, cert.getSubjectDN() );

        if( i == 0 )
            mCertPathTree->insertTopLevelItem(0, item );
        else
        {
            pPrevItem->addChild( item );
        }

        pPrevItem = item;
    }

    mCertPathTree->expandAll();
}

void CertInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mFieldTable->clear();
    mFieldTable->horizontalHeader()->setStretchLastSection(true);
    mFieldTable->setColumnCount(2);
    mFieldTable->setHorizontalHeaderLabels( sBaseLabels );
    mFieldTable->verticalHeader()->setVisible(false);
    mFieldTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect( mCheckBtn, SIGNAL(clicked()), this, SLOT(clickCheck()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
}

void CertInfoDlg::clickClose()
{
    this->hide();
}

void CertInfoDlg::clickField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mFieldTable->item( row, 1 );
    if( item == NULL ) return;

    mDetailText->setPlainText( item->text() );
}

void CertInfoDlg::clickCheck()
{
    int ret = 0;
    tabWidget->setCurrentIndex(1);

    BINList *pChainList = NULL;
    BIN     binCert = {0,0};

    for( int i = 0; i < cert_list_.size(); i++ )
    {
        CertRec cert = cert_list_.at(i);

        if( i == cert_list_.size() - 1 )
        {
            JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );
        }
        else
        {
            BIN bin = {0,0};
            JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &bin );

            if( pChainList == NULL )
                JS_BIN_createList( &bin, &pChainList );
            else
                JS_BIN_appendList( pChainList, &bin );

            JS_BIN_reset( &bin );
        }
    }

    ret = JS_PKI_checkValidPath( pChainList, NULL, &binCert );

    QString strRes = QString( "Ret: %1").arg( ret );
    mCertStatusText->setPlainText( strRes );

    if( pChainList ) JS_BIN_resetList( &pChainList );
    JS_BIN_reset( &binCert );
}

void CertInfoDlg::clearTable()
{
    int rowCnt = mFieldTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mFieldTable->removeRow(0);
}
