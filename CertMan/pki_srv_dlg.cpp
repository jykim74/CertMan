#include <QMenu>

#include "js_gen.h"
#include "js_net.h"
#include "js_adm.h"
#include "js_http.h"
#include "pki_srv_dlg.h"
#include "commons.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"
#include "config_rec.h"

static QStringList sNameList;

static QStringList sOCSPNameList = {
    "LOG_PATH", "LOG_LEVEL", "OCSP_HSM_LIB_PATH", "OCSP_HSM_SLOT_ID"
    "OCSP_HSM_PIN", "OCSP_HSM_KEY_ID", "OCSP_SRV_PRIKEY_NUM",
    "OCSP_SRV_PRIKEY_ENC", "OCSP_SRV_PRIKEY_PASSWD", "OCSP_SRV_CERT_NUM",
    "OCSP_HSM_USE", "OCSP_NEED_SIGN", "OCSP_MSG_DUMP",
    "SSL_CA_CERT_PATH", "SSL_CERT_PATH", "SSL_PRIKEY_PATH",
    "OCSP_PORT", "OCSP_SSL_PORT" };

static QStringList sCMPNameList = {
    "LOG_PATH", "LOG_LEVEL", "CA_HSM_LIB_PATH", "CA_HSM_SLOT_ID"
    "CA_HSM_PIN", "CA_HSM_KEY_ID", "CA_PRIKEY_NUM",
    "CA_PRIKEY_ENC", "CA_PRIKEY_PASSWD",
    "ROOTCA_CERT_NUM", "CA_CERT_NUM",
    "CA_HSM_USE", "CMP_MSG_DUMP", "ISSUER_NUM", "CERT_PROFILE",
    "SSL_CA_CERT_PATH", "SSL_CERT_PATH", "SSL_PRIKEY_PATH",
    "CMP_PORT", "CMP_SSL_PORT", "CA_KEY_GEN", "CA_PARAM" };

static QStringList sRegNameList = {
    "LOG_PATH", "LOG_LEVEL", "REG_HSM_LIB_PATH", "REG_HSM_SLOT_ID"
    "REG_HSM_PIN", "REG_HSM_KEY_ID", "REG_SRV_PRIKEY_NUM",
    "REG_SRV_PRIKEY_ENC", "REG_SRV_PRIKEY_PASSWD", "REG_SRV_CERT_NUM",
    "REG_HSM_USE", "REG_NEED_SIGN", "REG_MSG_DUMP",
    "SSL_CA_CERT_PATH", "SSL_CERT_PATH", "SSL_PRIKEY_PATH",
    "REG_PORT", "REG_SSL_PORT" };

static QStringList sTSPNameList = {
    "LOG_PATH", "LOG_LEVEL", "TSP_HSM_LIB_PATH", "TSP_HSM_SLOT_ID"
    "TSP_HSM_PIN", "TSP_HSM_KEY_ID", "TSP_SRV_PRIKEY_NUM",
    "TSP_SRV_PRIKEY_ENC", "TSP_SRV_PRIKEY_PASSWD", "TSP_SRV_CERT_NUM",
    "TSP_HSM_USE", "TSP_NEED_SIGN", "TSP_MSG_DUMP",
    "SSL_CA_CERT_PATH", "SSL_CERT_PATH", "SSL_PRIKEY_PATH",
    "TSP_PORT", "TSP_SSL_PORT" };

PKISrvDlg::PKISrvDlg(QWidget *parent) :
    QDialog(parent)
{
    kind_ = -1;
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

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
}

PKISrvDlg::~PKISrvDlg()
{

}

void PKISrvDlg::setSrvKind( int nKind )
{
    kind_ = nKind;

    if( kind_ == JS_GEN_KIND_OCSP_SRV )
        sNameList = sOCSPNameList;
    else if( kind_ == JS_GEN_KIND_TSP_SRV )
        sNameList = sTSPNameList;
    else if( kind_ == JS_GEN_KIND_CMP_SRV )
        sNameList = sCMPNameList;
    else if( kind_ == JS_GEN_KIND_REG_SRV )
        sNameList = sRegNameList;
}

void PKISrvDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void PKISrvDlg::closeEvent(QCloseEvent *event)
{
    int nSockFd = mSockText->text().toInt();

    if( nSockFd > 0 ) JS_NET_close( nSockFd );
}

const QString PKISrvDlg::getName()
{
    if( kind_ == JS_GEN_KIND_OCSP_SRV )
        return "OCSP";
    else if( kind_ == JS_GEN_KIND_TSP_SRV )
        return "TSP";
    else if( kind_ == JS_GEN_KIND_CMP_SRV )
        return "CMP";
    else if( kind_ == JS_GEN_KIND_REG_SRV )
        return "Reg";

    return "Service";
}

void PKISrvDlg::initialize()
{
    QString strTitle = QString( "%1 Server Information").arg( getName() );
    QString strPath = getBinPath();
    mServerPathText->setText( strPath );

    mTitleLabel->setText( strTitle );

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


    mProcText->setText( "0" );
    mIndexText->setText( "0" );

    loadTable();

    setEnableAdmin( false );
}

void PKISrvDlg::clearTable()
{
    int nRows = mConfigTable->rowCount();

    for( int i = 0; i < nRows; i++ )
    {
        mConfigTable->removeRow(0);
    }
}

void PKISrvDlg::setEnableAdmin( bool bVal )
{
    mListPidBtn->setEnabled( bVal );
    mGetProcBtn->setEnabled( bVal );
    mGetServiceBtn->setEnabled( bVal );
    mListThreadBtn->setEnabled( bVal );
    mGetThreadBtn->setEnabled( bVal );
    mResizeBtn->setEnabled( bVal );
    mStopBtn->setEnabled( bVal );
}

void PKISrvDlg::loadTable()
{
    DBMgr *dbMgr = manApplet->dbMgr();
    QList<ConfigRec> configList;

    clearTable();

    dbMgr->getConfigList( kind_, configList );

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

void PKISrvDlg::clickDel()
{
    QTableWidgetItem *item = mConfigTable->selectedItems().at(0);

    manApplet->dbMgr()->delConfigRec( item->text().toInt() );

    mConfigTable->removeRow(item->row());
}

void PKISrvDlg::clickAdd()
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
    config.setKind( kind_ );

    manApplet->dbMgr()->addConfigRec( config );

    loadTable();
    mValueText->clear();
}

void PKISrvDlg::clickFindFile()
{
    QString strPath = manApplet->curFile();

    QString strFileName = findFile( this, JS_FILE_TYPE_BER, strPath );

    if( strFileName.length() > 0 )
    {
        mValueText->setText( strFileName );
        manApplet->setCurFile( strFileName );
    }
}

void PKISrvDlg::clickFindServer()
{
    QString strPath = mServerPathText->text();

    QString strFileName = findFile( this, JS_FILE_TYPE_ALL, strPath );

    if( strFileName.length() > 0 ) mServerPathText->setText( strFileName );
}

void PKISrvDlg::clickCheck()
{
    int ret = 0;
    int nPort = 0;
    QString strURL;
    QString strValue;

    DBMgr* dbMgr = manApplet->dbMgr();
    QString strPKI = getName();
    QString strName = QString( "%1_PORT" ).arg( strPKI );

    if( kind_ == JS_GEN_KIND_OCSP_SRV )
        nPort = JS_OCSP_PORT;
    else if( kind_ == JS_GEN_KIND_TSP_SRV )
        nPort = JS_TSP_PORT;
    else if( kind_ == JS_GEN_KIND_CMP_SRV )
        nPort = JS_CMP_PORT;
    else if( kind_ == JS_GEN_KIND_REG_SRV )
        nPort = JS_REG_PORT;

    ret = dbMgr->getConfigValue( kind_, strName, strValue );
    if( ret == 1 ) nPort = strValue.toInt();

    strURL = QString("http://localhost:%1/PING").arg( nPort );

    ret = JS_HTTP_ping( strURL.toStdString().c_str() );
    if( ret == 0 )
    {
        manApplet->log( QString("%1 Server is started" ).arg( strPKI ));
        mOnBtn->setEnabled( true );
    }
    else
    {
        manApplet->elog( QString("%1 Server is not working" ).arg( strPKI ));
        mOnBtn->setEnabled(false);
    }
}

void PKISrvDlg::clickStart()
{
    QString strCmd;
    QString strServerPath = mServerPathText->text();
    QString strPKI = getName();
    QStringList strArgList;

    if( strServerPath.length() < 1 )
    {
        manApplet->warningBox( tr( "You have to find %1 Server file" ).arg( strPKI ), this );
        return;
    }

    if( QFile::exists( strServerPath ) == false )
    {
        manApplet->warningBox( tr( "The file %1 is not exist" ).arg( strServerPath ), this );
        return;
    }

    /*
    strArgList << "-d" << manApplet->dbMgr()->getDBPath();
    manApplet->log( QString( "Run Cmd: %1").arg( strServerPath ));
    */

    strCmd = strServerPath;
    strCmd += " -d ";
    strCmd += manApplet->dbMgr()->getDBPath();

    QProcess process;
//    process.startDetached( strServerPath, strArgList );
    process.startDetached( strCmd );
//    process.execute( strCmd );

    setBinPath( strServerPath );

    clickCheck();
}

void PKISrvDlg::slotConfigMenuRequested(QPoint pos)
{
    QMenu *menu = new QMenu(this);
    QAction *delAct = new QAction( tr("Delete"), this );
    connect( delAct, SIGNAL(triggered()), this, SLOT(deleteConfigMenu()));

    menu->addAction( delAct );
    menu->popup( mConfigTable->viewport()->mapToGlobal(pos));
}

void PKISrvDlg::deleteConfigMenu()
{
    QModelIndex idx = mConfigTable->currentIndex();

    QTableWidgetItem *item = mConfigTable->item(idx.row(), 0);

    manApplet->dbMgr()->delConfigRec( item->text().toInt() );

    mConfigTable->removeRow(idx.row());
}

void PKISrvDlg::clickConnect()
{
    int sockfd = -1;
    const char *pHost = "localhost";
    int nPort = -1;

    if( kind_ == JS_GEN_KIND_OCSP_SRV )
        nPort = JS_OCSP_PORT + 10;
    else if( kind_ == JS_GEN_KIND_TSP_SRV )
        nPort = JS_TSP_PORT + 10;
    else if( kind_ == JS_GEN_KIND_CMP_SRV )
        nPort = JS_CMP_PORT + 10;
    else if( kind_ == JS_GEN_KIND_REG_SRV )
        nPort = JS_REG_PORT + 10;

    sockfd = mSockText->text().toInt();

    if( sockfd > 0 )
    {
        JS_NET_close( sockfd );
        mConnectBtn->setText( tr("Connect" ));
        manApplet->log( "Admin is disconnected" );
        mSockText->clear();
        setEnableAdmin( false );
        return;
    }

    int ret = JS_ADM_Connect( pHost, nPort );
    if( ret < 0 )
    {
        manApplet->elog( QString("fail to connect admin server(%1:%2): %3").arg( pHost ).arg( nPort ).arg(ret));
        mSockText->clear();
    }
    else
    {
        manApplet->log( QString("admin service(%1:%2) is connected:%3").arg( pHost ).arg( nPort ).arg( ret ));
        mSockText->setText( QString("%1").arg(ret));
        mConnectBtn->setText( tr("Disconnect"));
        setEnableAdmin( true );
    }
}

void PKISrvDlg::clickListPid()
{
    int iRes = -1;
    int nSockFd = mSockText->text().toInt();

    JNumList *pNumList = NULL;

    int ret = JS_ADM_ListPid( nSockFd, &iRes, &pNumList );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to list pid: %1").arg(ret));
        mResText->clear();
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        mResText->setText( QString("%1").arg( iRes ) );

        JNumList *pCurList = pNumList;

        while( pCurList )
        {
            manApplet->log( QString( "Pid : %1" ).arg( pCurList->nNum ));
            pCurList = pCurList->pNext;
        }
    }

    JS_UTIL_resetNumList( &pNumList );
}

void PKISrvDlg::clickGetProc()
{
    int iRes = 0;

    JProcInfo *pstProcInfo = NULL;

    int nSockFd = mSockText->text().toInt();
    int nProcIndex = mProcText->text().toInt();

    int ret = JS_ADM_GetProc( nSockFd, &iRes, nProcIndex, &pstProcInfo );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to get proc: %1").arg(ret));
        mResText->clear();
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        mResText->setText( QString("%1").arg( iRes ) );

        JProcInfo *pCurList = pstProcInfo;

        while( pCurList )
        {
            logProcInfo( pCurList );
            pCurList = pCurList->pNext;
        }
    }


    JS_ADM_resetProcInfoList( &pstProcInfo );
}

void PKISrvDlg::clickGetService()
{
    int iRes = 0;
    int nSockFd = mSockText->text().toInt();
    int nProcIndex = mProcText->text().toInt();

    JServiceInfo *pstServiceInfo = NULL;
    int ret = JS_ADM_GetService( nSockFd, &iRes, nProcIndex, &pstServiceInfo );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to get service: %1").arg(ret));
        mResText->clear();
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        mResText->setText( QString("%1").arg( iRes ) );

        JServiceInfo *pCurList = pstServiceInfo;

        while( pCurList )
        {
            logServiceInfo( pCurList );
            pCurList = pCurList->pNext;
        }
    }

    JS_ADM_resetServiceInfoList( &pstServiceInfo );
}

void PKISrvDlg::clickListThread()
{
    int iRes = 0;
    int nSockFd = mSockText->text().toInt();
    int nProcIndex = mProcText->text().toInt();

    JThreadInfo *pstThInfo = NULL;

    int ret = JS_ADM_ListThread( nSockFd, &iRes, nProcIndex, &pstThInfo );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to list thread: %1").arg(ret));
        mResText->clear();
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        mResText->setText( QString("%1").arg( iRes ) );

        JThreadInfo *pCurList = pstThInfo;

        while( pCurList )
        {
            logThreadInfo( pCurList );
            pCurList = pCurList->pNext;
        }
    }

    JS_ADM_resetThreadInfoList( &pstThInfo );
}

void PKISrvDlg::clickGetThread()
{
    int iRes = 0;
    int nSockFd = mSockText->text().toInt();
    int nProcIndex = mProcText->text().toInt();
    int nIndex = mIndexText->text().toInt();

    JThreadInfo *pstThInfo = NULL;

    int ret = JS_ADM_GetThread( nSockFd, &iRes, nProcIndex, nIndex, &pstThInfo );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to get thread: %1").arg(ret));
        mResText->clear();
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        mResText->setText( QString("%1").arg( iRes ) );

        JThreadInfo *pCurList = pstThInfo;

        while( pCurList )
        {
            logThreadInfo( pCurList );
            pCurList = pCurList->pNext;
        }
    }

    JS_ADM_resetThreadInfoList( &pstThInfo );
}

void PKISrvDlg::clickResize()
{
    int iRes = 0;

    int nSockFd = mSockText->text().toInt();
    int nProcIndex = mProcText->text().toInt();
    int nSize = mIndexText->text().toInt();

    JNumList *pNumList = NULL;

    int ret = JS_ADM_Resize( nSockFd, &iRes, nProcIndex, nSize, &pNumList );

    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to resize: %1").arg(ret));
        mResText->clear();
    }
    else
    {
        manApplet->log( QString( "Result:%1").arg( iRes ));
        mResText->setText( QString("%1").arg( iRes ) );

        JNumList *pCurList = pNumList;

        while( pCurList )
        {
            manApplet->log( QString( "Pid : %1" ).arg( pCurList->nNum ));
            pCurList = pCurList->pNext;
        }
    }

    JS_UTIL_resetNumList( &pNumList );
}

void PKISrvDlg::clickStop()
{
    int nSockFd = mSockText->text().toInt();
    int ret = JS_ADM_StopService( nSockFd );

    mSockText->clear();
    mResText->clear();
}

void PKISrvDlg::logProcInfo( const JProcInfo *pProcInfo )
{
    manApplet->log( "========================================================================" );
    manApplet->log( "== Proc Information" );
    manApplet->log( "========================================================================" );
    if( pProcInfo == NULL ) return;

    manApplet->log( QString( "ListenFd          : %1").arg( pProcInfo->nListenFd ));
    manApplet->log( QString( "Port              : %1").arg( pProcInfo->nPort ));
    manApplet->log( QString( "InitThreadCnt     : %1").arg( pProcInfo->nInitThreadCnt ));
    manApplet->log( QString( "ServiceName       : %1").arg( pProcInfo->pServiceName ));
    manApplet->log( QString( "BindAddress       : %1").arg( pProcInfo->pBindAddress ? pProcInfo->pBindAddress : "" ));
    manApplet->log( "========================================================================" );
}

void PKISrvDlg::logServiceInfo( const JServiceInfo *pServiceInfo )
{
    manApplet->log( "========================================================================" );
    manApplet->log( "== Service Information" );
    manApplet->log( "========================================================================" );

    if( pServiceInfo == NULL ) return;

    manApplet->log( QString( "ServiceID         : %1").arg( pServiceInfo->nServiceID ) );
    manApplet->log( QString( "ServiceName       : %1").arg( pServiceInfo->pServiceName ) );
    manApplet->log( QString( "StartTime         : %1").arg( pServiceInfo->tStartTime ) );
    manApplet->log( QString( "ProcessID         : %1").arg( pServiceInfo->nProcessID ) );
    manApplet->log( QString( "BindAddress       : %1").arg( pServiceInfo->pBindAddress ? pServiceInfo->pBindAddress : "" ) );
    manApplet->log( QString( "Port              : %1").arg( pServiceInfo->nPort ) );
    manApplet->log( QString( "PoolSize          : %1").arg( pServiceInfo->nPoolSize ) );
    manApplet->log( QString( "WaitPoolCnt       : %1").arg( pServiceInfo->nWaitPoolCnt ) );
    manApplet->log( QString( "QueuedCnt         : %1").arg( pServiceInfo->nQueuedCnt ) );
    manApplet->log( QString( "ListenFd          : %1").arg( pServiceInfo->nListenFd ) );
    manApplet->log( "========================================================================" );
}

void PKISrvDlg::logThreadInfo( const JThreadInfo *pThInfo )
{
    manApplet->log( "========================================================================" );
    manApplet->log( "== Thread Information" );
    manApplet->log( "========================================================================" );

    if( pThInfo == NULL ) return;

    manApplet->log( QString( "Index            : %1" ).arg( pThInfo->nIndex ));
    manApplet->log( QString( "ThreadID         : %1" ).arg( pThInfo->nThreadID));
    manApplet->log( QString( "State            : %1" ).arg( pThInfo->cState ));
    manApplet->log( QString( "IsQuit           : %1" ).arg( pThInfo->nIsQuit ));
    manApplet->log( QString( "WorkCnt          : %1" ).arg( pThInfo->nWorkCnt ));
    manApplet->log( QString( "StartTime        : %1" ).arg( pThInfo->tStartTime ));
    manApplet->log( QString( "WorkTime         : %1" ).arg( pThInfo->tWorkTime ));
    manApplet->log( QString( "SockFd           : %1" ).arg( pThInfo->nSockFd ));
    manApplet->log( QString( "ServiceID        : %1" ).arg( pThInfo->nServiceID ));
    manApplet->log( QString( "ConnFlag         : %1" ).arg( pThInfo->nConnFlag ));
    manApplet->log( QString( "ClientIP         : %1" ).arg( pThInfo->sClientIP ));
    manApplet->log( "========================================================================" );
}


void PKISrvDlg::setBinPath( const QString strPath )
{
    QString strName = getName();
    QSettings   settings;

    QString strTarget = QString( "%1SrvPath" ).arg( strName );

    settings.beginGroup( "ServerBehavior" );
    settings.setValue( strTarget, strPath );
    settings.endGroup();
}

const QString PKISrvDlg::getBinPath()
{
    QString strPath;
    QString strName = getName();
    QString strTarget = QString( "%1SrvPath" ).arg( strName );

#if defined( Q_OS_WIN32 )
    QString strDefault = QString( "%1_srv.exe" ).arg( strName ).toLower();
#else
    QString strDefault = QString( "%1_srv" ).arg( strName ).toLower();
#endif

    QSettings   settings;
    settings.beginGroup( "ServerBehavior" );
    strPath = settings.value( strTarget, strDefault ).toString();
    settings.endGroup();

    return strPath;
}
