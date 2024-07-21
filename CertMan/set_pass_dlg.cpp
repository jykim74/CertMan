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
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
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
        mPasswdText->setFocus();
        return;
    }

    if( strPasswdConf.length() < 1 )
    {
        manApplet->warningBox( tr( "Please enter a confirm password" ), this );
        mPasswdConfirmText->setFocus();
        return;
    }

    if( strPasswd != strPasswdConf )
    {
        manApplet->warningBox( tr( "Password and confirm values are different"), this );
        mPasswdConfirmText->setFocus();
        return;

    }

    return QDialog::accept();
}
