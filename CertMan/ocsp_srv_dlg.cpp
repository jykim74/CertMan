#include <QMenu>

#include "js_gen.h"
#include "js_adm.h"
#include "js_http.h"
#include "ocsp_srv_dlg.h"
#include "commons.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"
#include "config_rec.h"

static QStringList sNameList = {
    "LOG_PATH", "LOG_LEVEL", "OCSP_HSM_LIB_PATH", "OCSP_HSM_SLOT_ID"
    "OCSP_HSM_PIN", "OCSP_HSM_KEY_ID", "OCSP_SRV_PRIKEY_NUM",
    "OCSP_SRV_PRIKEY_ENC", "OCSP_SRV_PRIKEY_PASSWD", "OCSP_SRV_CERT_NUM",
    "OCSP_HSM_USE", "OCSP_NEED_SIGN", "OCSP_MSG_DUMP",
    "SSL_CA_CERT_PATH", "SSL_CERT_PATH", "SSL_PRIKEY_PATH",
    "OCSP_PORT", "OCSP_SSL_PORT" };

OCSPSrvDlg::OCSPSrvDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mDelBtn, SIGNAL(clicked()), this, SLOT(clickDel()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFindServer()));
    connect( mCheckBtn, SIGNAL(clicked()), this, SLOT(clickCheck()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mFileFindBtn, SIGNAL(clicked()), this, SLOT(clickFindFile()));

    connect( mConfigTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotConfigMenuRequested(QPoint)));

    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mListPidBtn, SIGNAL(clicked()), this, SLOT(clickListPid()));
    connect( mGetProcBtn, SIGNAL(clicked()), this, SLOT(clickGetProc()));
    connect( mGetServiceBtn, SIGNAL(clicked()), this, SLOT(clickGetService()));
    connect( mListThreadBtn, SIGNAL(clicked()), this, SLOT(clickListThread()));
    connect( mGetThreadBtn, SIGNAL(clicked()), this, SLOT(clickGetThread()));
    connect( mResizeBtn, SIGNAL(clicked()), this, SLOT(clickResize()));
    connect( mStopBtn, SIGNAL(clicked()), this, SLOT(clickStop()));

    initialize();
}

OCSPSrvDlg::~OCSPSrvDlg()
{

}

void OCSPSrvDlg::initialize()
{
    mNameCombo->setEnabled( true );
    mNameCombo->addItems( sNameList );
    mNameCombo->setEditable( true );

    QStringList sConfigLabes = { tr( "Num" ), tr("Name"), tr("Value" ) };

    mConfigTable->setColumnCount( sConfigLabes.size() );
    mConfigTable->horizontalHeader()->setStretchLastSection(true);
    mConfigTable->setHorizontalHeaderLabels(sConfigLabes);
    mConfigTable->verticalHeader()->setVisible(false);
    mConfigTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mConfigTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mConfigTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mConfigTable->setColumnWidth(0, 60);
    mConfigTable->setColumnWidth(1, 200);

    mOnBtn->setDisabled(true);

    loadTable();
}

void OCSPSrvDlg::clearTable()
{
    int nRows = mConfigTable->rowCount();

    for( int i = 0; i < nRows; i++ )
    {
        mConfigTable->removeRow(0);
    }
}

void OCSPSrvDlg::loadTable()
{
    DBMgr *dbMgr = manApplet->dbMgr();
    QList<ConfigRec> configList;

    clearTable();

    dbMgr->getConfigList( JS_GEN_KIND_OCSP_SRV, configList );

    for( int i = 0; i < configList.size(); i++ )
    {
        ConfigRec config = configList.at(i);

        mConfigTable->insertRow(i);
        mConfigTable->setRowHeight(i, 10 );
        mConfigTable->setItem(i,0, new QTableWidgetItem(QString("%1").arg( config.getNum() )));
        mConfigTable->setItem(i,1, new QTableWidgetItem(QString("%1").arg( config.getName() )));
        mConfigTable->setItem(i,2, new QTableWidgetItem(QString("%1").arg( config.getValue() )));
    }
}

void OCSPSrvDlg::clickDel()
{
    QTableWidgetItem *item = mConfigTable->selectedItems().at(0);

    manApplet->dbMgr()->delConfigRec( item->text().toInt() );

    mConfigTable->removeRow(item->row());
}

void OCSPSrvDlg::clickAdd()
{
    ConfigRec config;

    QString strName = mNameCombo->currentText();
    QString strValue = mValueText->text();

    if( strValue.length() < 1 )
    {
        manApplet->warningBox( tr( "You have to insert value" ), this );
        return;
    }

    for( int i = 0; i < mConfigTable->rowCount(); i++ )
    {
        QTableWidgetItem *item = mConfigTable->item( i, 1 );

        if( item->text().toLower() == strName.toLower() )
        {
            manApplet->warningBox( tr( "%1 has already inserted" ).arg( strName ));
            return;
        }
    }

    config.setValue( strValue );
    config.setName( strName );
    config.setKind( JS_GEN_KIND_OCSP_SRV );

    manApplet->dbMgr()->addConfigRec( config );

    loadTable();
    mValueText->clear();
}

void OCSPSrvDlg::clickFindFile()
{
    QString strPath = manApplet->curFile();

    QString strFileName = findFile( this, JS_FILE_TYPE_BER, strPath );

    if( strFileName.length() > 0 )
    {
        mValueText->setText( strFileName );
        manApplet->setCurFile( strFileName );
    }
}

void OCSPSrvDlg::clickFindServer()
{
    QString strPath = mServerPathText->text();

    QString strFileName = findFile( this, JS_FILE_TYPE_BER, strPath );

    if( strFileName.length() > 0 ) mServerPathText->setText( strFileName );
}

void OCSPSrvDlg::clickCheck()
{
    int ret = 0;
    int nPort = JS_OCSP_PORT;
    QString strURL;
    QString strValue;

    DBMgr* dbMgr = manApplet->dbMgr();

    ret = dbMgr->getConfigValue( JS_GEN_KIND_OCSP_SRV, "OCSP_PORT", strValue );
    if( ret == 1 ) nPort = strValue.toInt();

    strURL = QString("http://localhost:%1/PING").arg( nPort );

    ret = JS_HTTP_ping( strURL.toStdString().c_str() );
    if( ret == 0 )
    {
        manApplet->log( "OCSP Server is started" );
        mOnBtn->setEnabled( true );
    }
    else
    {
        manApplet->elog( "OCSP Server is not working" );
        mOnBtn->setEnabled(false);
    }
}

void OCSPSrvDlg::clickStart()
{
    QString strCmd;
    QString strServerPath = mServerPathText->text();

    if( strServerPath.length() < 1 )
    {
        manApplet->warningBox( tr( "You have to find OCSP Server file" ), this );
        return;
    }

    strCmd = strServerPath;
    strCmd += " -d ";
    strCmd += manApplet->dbMgr()->getDBPath();

    manApplet->log( QString( "Run Cmd: %1").arg( strCmd ));

    QProcess *process = new QProcess();
    process->setProgram( strCmd );
    process->start();
}

void OCSPSrvDlg::slotConfigMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteConfigMenu()));

    menu->addAction( delAct );
    menu->popup( mConfigTable->viewport()->mapToGlobal(pos));
}

void OCSPSrvDlg::deleteConfigMenu()
{
    QModelIndex idx = mConfigTable->currentIndex();

    QTableWidgetItem *item = mConfigTable->item(idx.row(), 0);

    manApplet->dbMgr()->delConfigRec( item->text().toInt() );

    mConfigTable->removeRow(idx.row());
}

void OCSPSrvDlg::clickConnect()
{
    const char *pHost = "localhost";
    int nPort = JS_OCSP_PORT + 10;

    int ret = JS_ADM_Connect( pHost, nPort );
    if( ret < 0 )
    {
        manApplet->elog( QString("fail to connect admin server: %1").arg(ret));
        sockfd_ = -1;
    }
    else
    {
        manApplet->log( QString("admin service is connected:%1").arg( ret ));
        sockfd_ = ret;
    }
}

void OCSPSrvDlg::clickListPid()
{
    int iRes = -1;
    JNumList *pNumList = NULL;
    JNumList *pCurList = NULL;
    JNumList *pTmpList = NULL;

    int ret = JS_ADM_ListPid( sockfd_, &iRes, &pNumList );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to list pid: %1").arg(ret));
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        pCurList = pNumList;

        while( pCurList )
        {
            manApplet->log( QString( "Pid : %1").arg( pCurList->nNum ));
            pTmpList = pCurList;
            JS_free( pTmpList );

            pCurList = pCurList->pNext;
        }
    }
}

void OCSPSrvDlg::clickGetProc()
{
    int iRes = 0;
    int nIndex = 0;
    JProcInfo *pstProcInfo = NULL;

    int ret = JS_ADM_GetProc( sockfd_, &iRes, nIndex, &pstProcInfo );
}

void OCSPSrvDlg::clickGetService()
{
    int iRes = 0;
    int nIndex = 0;

    JServiceInfo *pstServiceInfo = NULL;
    int ret = JS_ADM_GetService( sockfd_, &iRes, nIndex, &pstServiceInfo );
}

void OCSPSrvDlg::clickListThread()
{
    int iRes = 0;
    int nIndex = 0;
    JThreadInfo *pstThInfo = NULL;

    int ret = JS_ADM_ListThread( sockfd_, &iRes, nIndex, &pstThInfo );
}

void OCSPSrvDlg::clickGetThread()
{
    int iRes = 0;
    int nProcIndex = 0;
    int nIndex = 0;
    JThreadInfo *pstThInfo = NULL;

    int ret = JS_ADM_GetThread( sockfd_, &iRes, nProcIndex, nIndex, &pstThInfo );
}

void OCSPSrvDlg::clickResize()
{
    int iRes = 0;
    int nSize = 0;
    int nProcIndex = 0;

    JNumList *pNumList = NULL;

    int ret = JS_ADM_Resize( sockfd_, &iRes, nProcIndex, nSize, &pNumList );
}

void OCSPSrvDlg::clickStop()
{
    int ret = JS_ADM_StopService( sockfd_ );
}
