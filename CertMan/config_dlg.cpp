#include "js_gen.h"

#include "config_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"
#include "config_rec.h"
#include "commons.h"

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

void ConfigDlg::setFixKind( int nKind )
{
    mKindText->setText( QString("%1").arg( nKind ));
    mKindText->setReadOnly(true);
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
    {
        dbMgr->modConfigRec( cur_num_, config );
        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_MOD_CONFIG, "" );

    }
    else
    {
        dbMgr->addConfigRec( config );
        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_ADD_CONFIG, "" );
    }

    manApplet->mainWindow()->createRightConfigList();
    close();
}
