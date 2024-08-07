/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "tst_info_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"

#include "js_bin.h"
#include "js_tsp.h"
#include "tsp_rec.h"


TSTInfoDlg::TSTInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    memset( &bin_tst_, 0x00, sizeof(BIN));
    setupUi(this);

    connect( mInfoTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickField(QModelIndex)));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TSTInfoDlg::~TSTInfoDlg()
{
    JS_BIN_reset( &bin_tst_);
}

void TSTInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void TSTInfoDlg::clickField( QModelIndex index )
{
    int row = index.row();
    QTableWidgetItem *item0 = mInfoTable->item( row, 0 );
    QTableWidgetItem* item1 = mInfoTable->item( row, 1 );

    if( item0 == NULL || item1 == NULL ) return;

    mDataText->setPlainText( item1->text() );
}


void TSTInfoDlg::setTST( const BIN *pTST )
{
    if( pTST == NULL ) return;

    JS_BIN_reset( &bin_tst_ );
    JS_BIN_copy( &bin_tst_, pTST );
}

void TSTInfoDlg::initialize()
{
    int i = 0;
    int ret = 0;

    JTSTInfo    sTSTInfo;
    QString strAccuracy;
    QString strMsgImprint;

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    clearTable();

    ret = JS_TSP_decodeTSTInfo( &bin_tst_, &sTSTInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "Failed to decode TST message [%1]").arg(ret), this );
        this->hide();
        goto end;
    }


    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Version")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nVersion)));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Order")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nOrder)));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Serial")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nSerial)));
    i++;

    if( sTSTInfo.pPolicy )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Policy")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pPolicy)));
        i++;
    }

    if( sTSTInfo.pGenName )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("GenName")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pGenName)));
        i++;
    }

    if( sTSTInfo.pGenTime )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("GenTime")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pGenTime)));
        i++;
    }

    if( sTSTInfo.pNonce )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setRowHeight( i, 10 );
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Nonce")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pNonce)));
        i++;
    }


    strAccuracy = QString( "Sec:%1 millis:%2 micro:%3")
            .arg( sTSTInfo.sAccuracy.nSec )
            .arg( sTSTInfo.sAccuracy.nMiliSec )
            .arg( sTSTInfo.sAccuracy.nMicroSec );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Accuracy")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(strAccuracy)));
    i++;


    strMsgImprint = QString( "%1|%2")
            .arg( sTSTInfo.sMsgImprint.pAlg )
            .arg( sTSTInfo.sMsgImprint.pImprint );

    mInfoTable->insertRow(i);
    mInfoTable->setRowHeight( i, 10 );
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("MsgImprint")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(strMsgImprint)));
    i++;

end :
    JS_TSP_resetTSTInfo( &sTSTInfo );
}

void TSTInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";

    mInfoTable->clear();
    mInfoTable->horizontalHeader()->setStretchLastSection(true);
    mInfoTable->setColumnCount(2);
    mInfoTable->setHorizontalHeaderLabels( sBaseLabels );
    mInfoTable->verticalHeader()->setVisible(false);
    mInfoTable->horizontalHeader()->setStyleSheet( style );
    mInfoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mInfoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

void TSTInfoDlg::clearTable()
{
    int rowCnt = mInfoTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mInfoTable->removeRow(0);
}
