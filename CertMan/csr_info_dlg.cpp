/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "csr_info_dlg.h"
#include "commons.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_pki_tools.h"

CSRInfoDlg::CSRInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    csr_num_ = -1;
    setupUi(this);

    connect( mFieldTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
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
    mFieldTable->setSelectionMode(QAbstractItemView::SingleSelection);
    mFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mFieldTable->setColumnWidth( 0, 140 );
}

void CSRInfoDlg::initialize()
{
    int ret = 0;
    BIN binCSR = {0,0};
    BIN binPub = {0,0};

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( csr_num_ < 0 )
    {
        manApplet->warningBox( tr( "Select a CSR"), this );
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
        manApplet->warningBox( tr("fail to obtain CSR information [%1]").arg(ret), this );
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
    mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sReqInfo.bVerify ? "Verify" : "No verify")));
    i++;

    if( sReqInfo.pPublicKey )
    {
        int nKeyType = -1;
        int nOption = -1;

        QString strAlg;
        QString strParam;

        JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
        JS_PKI_getPubKeyInfo( &binPub, &nKeyType, &nOption );

        strAlg = JS_PKI_getKeyAlgName( nKeyType );

        if( nKeyType == JS_PKI_KEY_TYPE_ECDSA )
        {
            strParam = JS_PKI_getSNFromNid( nOption );
        }
        else if( nKeyType == JS_PKI_KEY_TYPE_RSA || nKeyType == JS_PKI_KEY_TYPE_DSA )
        {
            strParam = QString( "%1" ).arg( nOption );
        }

        QTableWidgetItem *item = NULL;

        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("PublicKey")));

        if( strParam.length() > 0 )
            item = new QTableWidgetItem(QString("%1 (%2)").arg( strAlg ).arg( strParam ));
        else
            item = new QTableWidgetItem(QString("%1").arg(strAlg));

        item->setData( Qt::UserRole, QString( sReqInfo.pPublicKey ) );
        mFieldTable->setItem( i, 1, item );
        i++;
    }

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

    if( sReqInfo.pUnstructuredName )
    {
        mFieldTable->insertRow(i);
        mFieldTable->setRowHeight(i,10);
        mFieldTable->setItem(i, 0, new QTableWidgetItem(tr("UnstructuredName")));
        mFieldTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sReqInfo.pUnstructuredName)));
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
    JS_BIN_reset( &binPub );
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
    QTableWidgetItem *item0 = mFieldTable->item( row, 0 );
    QTableWidgetItem* item1 = mFieldTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    if( item0->text() == tr( "PublicKey" ) )
    {
        QString strPub = item1->data(Qt::UserRole).toString();
        mDetailText->setPlainText( strPub );
    }
    else
    {
        mDetailText->setPlainText( item1->text() );
    }
}
