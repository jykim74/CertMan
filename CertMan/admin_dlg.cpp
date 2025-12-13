/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "js_gen.h"
#include "admin_dlg.h"

#include "db_mgr.h"
#include "admin_rec.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "commons.h"
#include "man_tree_view.h"


const QStringList kAdminType = { "Invalid", "Master", "Admin", "Audit" };

AdminDlg::AdminDlg(QWidget *parent) :
    QDialog(parent)
{
    seq_ = -1;
    edit_mode_ = false;
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mRegisterBtn, SIGNAL(clicked()), this, SLOT(clickRegister()));
    connect( mModifyBtn, SIGNAL(clicked()), this, SLOT(clickModify()));
    connect( mDeleteBtn, SIGNAL(clicked()), this, SLOT(clickDelete()));

    mPasswordText->setEchoMode(QLineEdit::Password);

    initialize();
    mRegisterBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

AdminDlg::~AdminDlg()
{

}

void AdminDlg::initialize()
{
    mStatusCombo->addItems( kStatusList );
    mStatusCombo->setCurrentIndex( 2 );

    mTypeCombo->addItems( kAdminType );
    mTypeCombo->setCurrentIndex( 2 );
}

void AdminDlg::setEditMode(bool bVal)
{
    if( bVal == true )
        mModifyBtn->setDefault( true );
    else
        mRegisterBtn->setDefault(true );

    edit_mode_ = bVal;
}

void AdminDlg::setSeq(int nSeq)
{
    seq_ = nSeq;
}

void AdminDlg::showEvent(QShowEvent *event)
{
    if( edit_mode_ )
    {
        DBMgr *dbMgr = manApplet->dbMgr();

        mRegisterBtn->hide();
        mModifyBtn->show();
        mDeleteBtn->show();

        AdminRec admin;
        dbMgr->getAdminRec( seq_, admin );
        mNameText->setText( admin.getName() );
        mPasswordText->setText( admin.getPassword() );
        mEmailText->setText( admin.getEmail() );

        mStatusCombo->setCurrentIndex(admin.getStatus());
        mTypeCombo->setCurrentIndex(admin.getType());
    }
    else
    {
        mRegisterBtn->show();
        mModifyBtn->hide();
        mDeleteBtn->hide();
    }
}

void AdminDlg::clickClose()
{
    close();
}

void AdminDlg::clickRegister()
{
    AdminRec admin;
    DBMgr *dbMgr = manApplet->dbMgr();

    QString strName = mNameText->text();
    QString strPassword = mPasswordText->text();
    QString strEmail = mEmailText->text();
    int nStatus = mStatusCombo->currentIndex();
    int nType = mTypeCombo->currentIndex();
    int nSeq = dbMgr->getNextVal( "TB_ADMIN" );

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter a name"), this );
        mNameText->setFocus();
        return;
    }

    if( strPassword.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter a password" ), this );
        mPasswordText->setFocus();
        return;
    }

    if( mGenPasswordMACCheck->isChecked() )
    {
        BIN binMAC = {0,0};
        JS_GEN_genPasswdHMAC( strPassword.toStdString().c_str(), &binMAC );
        strPassword = getHexString( &binMAC );
        JS_BIN_reset( &binMAC );
    }

    if( strEmail.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter a email" ), this );
        mEmailText->setFocus();
        return;
    }

    admin.setSeq( nSeq );
    admin.setName( strName );
    admin.setPassword( strPassword );
    admin.setEmail( strEmail );
    admin.setStatus( nStatus );
    admin.setType( nType );

    dbMgr->addAdminRec( admin );
//    manApplet->mainWindow()->createRightAdminList();
    manApplet->clickTreeMenu( CM_ITEM_TYPE_ADMIN );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_REG_ADMIN, "" );

    QDialog::accept();
}

void AdminDlg::clickDelete()
{
    if( seq_ < 0 )
    {
        manApplet->warningBox( tr("No admin selected"), this );
        return;
    }

    DBMgr *dbMgr = manApplet->dbMgr();
    dbMgr->delAdminRec( seq_ );
//    manApplet->mainWindow()->createRightAdminList();
    manApplet->clickTreeMenu( CM_ITEM_TYPE_ADMIN );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_DEL_ADMIN, "" );

    QDialog::accept();
}

void AdminDlg::clickModify()
{
    if( seq_ < 0 )
    {
        manApplet->warningBox( tr("No admin selected"), this );
        return;
    }

    AdminRec admin;
    DBMgr *dbMgr = manApplet->dbMgr();

    QString strName = mNameText->text();
    QString strPassword = mPasswordText->text();
    QString strEmail = mEmailText->text();
    int nStatus = mStatusCombo->currentIndex();
    int nType = mTypeCombo->currentIndex();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("Please enter a name"), this );
        mNameText->setFocus();
        return;
    }

    if( strPassword.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter a password" ), this );
        mPasswordText->setFocus();
        return;
    }

    if( mGenPasswordMACCheck->isChecked() )
    {
        BIN binMAC = {0,0};
        JS_GEN_genPasswdHMAC( strPassword.toStdString().c_str(), &binMAC );
        strPassword = getHexString( &binMAC );
        JS_BIN_reset( &binMAC );
    }

    if( strEmail.isEmpty() )
    {
        manApplet->warningBox( tr( "Please enter a email" ), this );
        mEmailText->setFocus();
        return;
    }

    admin.setName( strName );
    admin.setPassword( strPassword );
    admin.setEmail( strEmail );
    admin.setStatus( nStatus );
    admin.setType( nType );

    dbMgr->modAdminRec( seq_, admin );
//    manApplet->mainWindow()->createRightAdminList();
    manApplet->clickTreeMenu( CM_ITEM_TYPE_ADMIN );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_MOD_ADMIN, "" );

    QDialog::accept();
}
