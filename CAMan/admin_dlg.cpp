#include "admin_dlg.h"

#include "db_mgr.h"
#include "admin_rec.h"
#include "man_applet.h"
#include "mainwindow.h"


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
}

AdminDlg::~AdminDlg()
{

}

void AdminDlg::setEditMode(bool bVal)
{
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
        DBMgr *dbMgr = manApplet->mainWindow()->dbMgr();

        mRegisterBtn->hide();
        mModifyBtn->show();
        mDeleteBtn->show();

        AdminRec admin;
        dbMgr->getAdminRec( seq_, admin );
        mNameText->setText( admin.getName() );
        mPasswordText->setText( admin.getPassword() );
        mEmailText->setText( admin.getEmail() );
        mStatusText->setText( QString("%1").arg(admin.getStatus()));
        mTypeText->setText( QString("%1").arg(admin.getType()));
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
    DBMgr *dbMgr = manApplet->mainWindow()->dbMgr();

    QString strName = mNameText->text();
    QString strPassword = mPasswordText->text();
    QString strEmail = mEmailText->text();
    QString strStatus = mStatusText->text();
    QString strType = mTypeText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("You have to set name"), this );
        return;
    }

    if( strPassword.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to set password" ), this );
        return;
    }

    if( strEmail.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to set email" ), this );
        return;
    }

    admin.setName( strName );
    admin.setPassword( strPassword );
    admin.setEmail( strEmail );
    admin.setStatus( strStatus.toInt() );
    admin.setType( strType.toInt() );

    dbMgr->addAdminRec( admin );
    manApplet->mainWindow()->createRightAdminList();
    QDialog::accept();
}

void AdminDlg::clickDelete()
{
    if( seq_ < 0 )
    {
        manApplet->warningBox( tr("Admin is not selected"), this );
        return;
    }

    DBMgr *dbMgr = manApplet->mainWindow()->dbMgr();
    dbMgr->delAdminRec( seq_ );
    manApplet->mainWindow()->createRightAdminList();
    QDialog::accept();
}

void AdminDlg::clickModify()
{
    if( seq_ < 0 )
    {
        manApplet->warningBox( tr("Admin is not selected"), this );
        return;
    }

    AdminRec admin;
    DBMgr *dbMgr = manApplet->mainWindow()->dbMgr();

    QString strName = mNameText->text();
    QString strPassword = mPasswordText->text();
    QString strEmail = mEmailText->text();
    QString strStatus = mStatusText->text();
    QString strType = mTypeText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("You have to set name"), this );
        return;
    }

    if( strPassword.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to set password" ), this );
        return;
    }

    if( strEmail.isEmpty() )
    {
        manApplet->warningBox( tr( "You have to set email" ), this );
        return;
    }

    admin.setName( strName );
    admin.setPassword( strPassword );
    admin.setEmail( strEmail );
    admin.setStatus( strStatus.toInt() );
    admin.setType( strType.toInt() );

    dbMgr->modAdminRec( seq_, admin );
    manApplet->mainWindow()->createRightAdminList();
    QDialog::accept();
}
