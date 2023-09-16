#include "csr_info_dlg.h"
#include "commons.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"

CSRInfoDlg::CSRInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    csr_num_ = -1;
    setupUi(this);

    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
}

CSRInfoDlg::~CSRInfoDlg()
{

}

void CSRInfoDlg::setCSRNum(int nNum)
{
    csr_num_ = nNum;
}

void CSRInfoDlg::showEvent(QShowEvent *event)
{
    initUI();
    initialize();
}

void CSRInfoDlg::initUI()
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
    mFieldTable->setColumnWidth( 0, 140 );
}

void CSRInfoDlg::initialize()
{
    int ret = 0;
    BIN binCSR = {0, 0};

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( csr_num_ < 0 )
    {
        manApplet->warningBox( tr( "Select CSR"), this );
        this->hide();
        return;
    }

    JReqInfo sReqInfo;
    ReqRec req;
    JExtensionInfoList *pExtInfoList = NULL;
    int i = 0;

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    dbMgr->getReqRec( csr_num_, req );
    JS_BIN_decodeHex( req.getCSR().toStdString().c_str(), &binCSR );

    ret = JS_PKI_getReqInfo( &binCSR, &sReqInfo, 1, &pExtInfoList );

    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to get CSR information"), this );
        goto end;
    }

    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(sReqInfo.nVersion + 1)));
    i++;

    if( sReqInfo.pSubjectDN )
    {
        QString name = QString::fromUtf8( sReqInfo.pSubjectDN );

        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SubjectName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg( name )));
        i++;
    }

    mFieldTable->insertRow(i);
    mFieldTable->setRowHeight(i,10);
    mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Verify")));
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sReqInfo.bVerify ? "Verify" : "Not Verify")));
    i++;

    if( sReqInfo.pSignAlgorithm )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("SigAlgorithm")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sReqInfo.pSignAlgorithm)));
        i++;
    }

    if( sReqInfo.pSignature )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Signature")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sReqInfo.pSignature)));
        i++;
    }

    if( sReqInfo.pChallenge )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("Challenge")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sReqInfo.pChallenge)));
        i++;
    }

    if( pExtInfoList )
    {
        JExtensionInfoList *pCurList = pExtInfoList;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            QTableWidgetItem *item = new QTableWidgetItem( strValue );
            if( bCrit )
                item->setIcon(QIcon(":/images/critical.png"));
            else
                item->setIcon(QIcon(":/images/normal.png"));

            mFieldTable->insertRow(i);
            mFieldTable->setRowHeight(i,10);

            mFieldTable->setItem(i,0, getExtNameItem( strSN ));
            mFieldTable->setItem(i, 1, item );


            pCurList = pCurList->pNext;
            i++;
        }
    }

end :
    JS_BIN_reset( &binCSR );
    JS_PKI_resetReqInfo( &sReqInfo );
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
}

QTableWidgetItem* CSRInfoDlg::getExtNameItem( const QString strSN )
{
    QTableWidgetItem* item = NULL;

    if( strSN == JS_PKI_ExtNameAIA )
        item = new QTableWidgetItem( tr( "authorityInfoAccess" ));
    else if( strSN == JS_PKI_ExtNameAKI )
        item = new QTableWidgetItem( tr( "authorityKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameBC )
        item = new QTableWidgetItem( tr( "basicConstraints" ) );
    else if( strSN == JS_PKI_ExtNameCRLDP )
        item = new QTableWidgetItem( tr( "crlDistributionPoints" ) );
    else if( strSN == JS_PKI_ExtNameEKU )
        item = new QTableWidgetItem( tr( "extendedKeyUsage" ) );
    else if( strSN == JS_PKI_ExtNameIAN )
        item = new QTableWidgetItem( tr( "issuerAltName" ) );
    else if( strSN == JS_PKI_ExtNameKeyUsage )
        item = new QTableWidgetItem( tr( "keyUsage" ) );
    else if( strSN == JS_PKI_ExtNameNC )
        item = new QTableWidgetItem( tr( "nameConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePolicy )
        item = new QTableWidgetItem( tr( "certificatePolicies" ) );
    else if( strSN == JS_PKI_ExtNamePC )
        item = new QTableWidgetItem( tr( "policyConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePM )
        item = new QTableWidgetItem( tr( "policyMappings" ) );
    else if( strSN == JS_PKI_ExtNameSKI )
        item = new QTableWidgetItem( tr( "subjectKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameSAN )
        item = new QTableWidgetItem( tr( "subjectAltName" ) );
    else if( strSN == JS_PKI_ExtNameCRLNum )
        item = new QTableWidgetItem( tr( "crlNumber" ) );
    else if( strSN == JS_PKI_ExtNameIDP )
        item = new QTableWidgetItem( tr( "issuingDistributionPoint" ) );
    else if( strSN == JS_PKI_ExtNameCRLReason )
        item = new QTableWidgetItem( tr( "CRLReason" ) );
    else
        item = new QTableWidgetItem( strSN );


    return item;
}

void CSRInfoDlg::clickField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mFieldTable->item( row, 1 );
    if( item == NULL ) return;

    mDetailText->setPlainText( item->text() );
}
