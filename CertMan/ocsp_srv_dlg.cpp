#include <QMenu>

#include "js_gen.h"
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

}

void OCSPSrvDlg::clickStart()
{
    QString strCmd = QString( "%1 -d %2").arg(mServerPathText->text()).arg( manApplet->dbMgr()->getDBPath() );


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