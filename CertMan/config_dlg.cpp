/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "js_gen.h"

#include "config_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "db_mgr.h"
#include "config_rec.h"
#include "commons.h"
#include "man_tree_view.h"

const QStringList kKindList = { "CMPServer", "REGServer", "OCSPServer", "TSPServer", "CCServer", "KMSServer" };

ConfigDlg::ConfigDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    cur_num_ = -1;

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    mOKBtn->setDefault(true);


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ConfigDlg::~ConfigDlg()
{

}

void ConfigDlg::initialize()
{
    mKindCombo->addItems( kKindList );
}

void ConfigDlg::setCurNum(int nNum)
{
    cur_num_ = nNum;
}

void ConfigDlg::setFixKind( int nKind )
{
    QString strKind = JS_GEN_getKindName( nKind );
    mKindCombo->clear();
    mKindCombo->addItem( strKind );
}

void ConfigDlg::showEvent(QShowEvent *event)
{
    initialize();

    if( cur_num_ > 0 )
    {
        DBMgr* dbMgr = manApplet->dbMgr();

        ConfigRec config;
        dbMgr->getConfigRec( cur_num_, config );
        QString strKind = JS_GEN_getKindName( config.getKind() );

        mNumText->setText( QString("%1").arg(config.getNum()));
//        mKindCombo->setCurrentText( strKind );
        setFixKind( config.getKind() );
        mNameText->setText( config.getName());
        mValueText->setText( config.getValue());
    }
}

void ConfigDlg::clickOK()
{
    ConfigRec config;
    DBMgr *dbMgr = manApplet->dbMgr();

    QString strKind = mKindCombo->currentText();
    QString strName = mNameText->text();
    QString strValue = mValueText->text();

    if( strKind.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a kind" ), this );
        return;
    }

    if( strName.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a name" ), this );
        mNameText->setFocus();
        return;
    }

    if( strValue.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a value" ), this );
        mValueText->setFocus();
        return;
    }

    int nKind = JS_GEN_getKindNum( strKind.toStdString().c_str() );

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

//    manApplet->mainWindow()->createRightConfigList( nKind );
    manApplet->mainWindow()->clickTreeMenu( CM_ITEM_TYPE_CONFIG, nKind );
    manApplet->messageBox( tr("Added settings"), this );

    close();
}
