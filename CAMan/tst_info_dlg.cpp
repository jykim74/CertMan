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
    seq_ = -1;
    setupUi(this);
    initUI();
}

TSTInfoDlg::~TSTInfoDlg()
{

}

void TSTInfoDlg::setSeq(int nSeq)
{
    seq_ = nSeq;
}

void TSTInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void TSTInfoDlg::initialize()
{
    int i = 0;
    int ret = 0;
    BIN binTST = {0,0};
    JTSTInfo    sTSTInfo;
    QString strAccuracy;
    QString strMsgImprint;

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    if( seq_ < 0 )
    {
        manApplet->warningBox( tr( "You have to set TST sequece"), this );
        this->hide();
        return;
    }

    clearTable();

    TSPRec tspRec;
    dbMgr->getTSPRec( seq_, tspRec );

    JS_BIN_decodeHex( tspRec.getTSTInfo().toStdString().c_str(), &binTST );

    ret = JS_TSP_decodeTSTInfo( &binTST, &sTSTInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "Fail to decode TST message"), this );
        this->hide();
        goto end;
    }

    mInfoTable->insertRow(i);
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Version")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nVersion)));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Order")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nOrder)));
    i++;

    mInfoTable->insertRow(i);
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Serial")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.nSerial)));
    i++;

    if( sTSTInfo.pPolicy )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Policy")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pPolicy)));
        i++;
    }

    if( sTSTInfo.pGenName )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("GenName")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pGenName)));
        i++;
    }

    if( sTSTInfo.pGenTime )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("GenTime")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pGenTime)));
        i++;
    }

    if( sTSTInfo.pNonce )
    {
        mInfoTable->insertRow(i);
        mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Nonce")));
        mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(sTSTInfo.pNonce)));
        i++;
    }


    strAccuracy = QString( "Sec:%1 millis:%2 micro:%3")
            .arg( sTSTInfo.sAccuracy.nSec )
            .arg( sTSTInfo.sAccuracy.nMiliSec )
            .arg( sTSTInfo.sAccuracy.nMicroSec );

    mInfoTable->insertRow(i);
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("Accuracy")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(strAccuracy)));
    i++;


    strMsgImprint = QString( "%1|%2")
            .arg( sTSTInfo.sMsgImprint.pAlg )
            .arg( sTSTInfo.sMsgImprint.pImprint );

    mInfoTable->insertRow(i);
    mInfoTable->setItem( i, 0, new QTableWidgetItem(QString("MsgImprint")));
    mInfoTable->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(strMsgImprint)));
    i++;

end :
    JS_TSP_resetTSTInfo( &sTSTInfo );
    JS_BIN_reset( &binTST );
}

void TSTInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mInfoTable->clear();
    mInfoTable->horizontalHeader()->setStretchLastSection(true);
    mInfoTable->setColumnCount(2);
    mInfoTable->setHorizontalHeaderLabels( sBaseLabels );
    mInfoTable->verticalHeader()->setVisible(false);
}

void TSTInfoDlg::clearTable()
{
    int rowCnt = mInfoTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mInfoTable->removeRow(0);
}
