/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "set_pass_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"

SetPassDlg::SetPassDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mUsePasswdCheck, SIGNAL(clicked()), this, SLOT(checkUsePasswd()));

    initialize();
}

SetPassDlg::~SetPassDlg()
{

}

void SetPassDlg::initialize()
{
    mUsePasswdCheck->setChecked(true);
}

void SetPassDlg::checkUsePasswd()
{
    bool bVal = mUsePasswdCheck->isChecked();

    mPasswdGroup->setEnabled( bVal );
}

void SetPassDlg::accept()
{
    if( mUsePasswdCheck->isChecked() == false )
        return QDialog::accept();

    QString strPasswd = mPasswdText->text();
    QString strPasswdConf = mPasswdConfirmText->text();

    if( strPasswd.length() < 1 )
    {
        manApplet->warningBox( tr( "Please enter a password"), this );
        return;
    }

    if( strPasswd != strPasswdConf )
    {
        manApplet->warningBox( tr( "Password and confirm values are different"), this );
        return;

    }

    return QDialog::accept();
}
