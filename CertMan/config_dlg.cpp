#include "config_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"
#include "config_rec.h"

ConfigDlg::ConfigDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    cur_num_ = -1;

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
}

ConfigDlg::~ConfigDlg()
{

}

void ConfigDlg::setCurNum(int nNum)
{
    cur_num_ = nNum;
}

void ConfigDlg::showEvent(QShowEvent *event)
{
    if( cur_num_ > 0 )
    {
        DBMgr* dbMgr = manApplet->dbMgr();

        ConfigRec config;
        dbMgr->getConfigRec( cur_num_, config );

        mNumText->setText( QString("%1").arg(config.getNum()));
        mKindText->setText( QString( "%1").arg(config.getKind()));
        mNameText->setText( config.getName());
        mValueText->setText( config.getValue());
    }
}

void ConfigDlg::clickOK()
{
    ConfigRec config;
    DBMgr *dbMgr = manApplet->dbMgr();

    int nKind = mKindText->text().toInt();
    QString strName = mNameText->text();
    QString strValue = mValueText->text();

    config.setKind( nKind );
    config.setName( strName );
    config.setValue( strValue );

    if( cur_num_ > 0 )
        dbMgr->modConfigRec( cur_num_, config );
    else
        dbMgr->addConfigRec( config );

    manApplet->mainWindow()->createRightConfigList();
    close();
}