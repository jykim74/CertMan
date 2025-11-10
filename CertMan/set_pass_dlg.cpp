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
    initUI();

    connect( mUsePassCheck, SIGNAL(clicked()), this, SLOT(checkUsePasswd()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    initialize();
}

SetPassDlg::~SetPassDlg()
{

}

void SetPassDlg::setHead( const QString& strHead )
{
    mHeadLabel->setText( strHead );
}

void SetPassDlg::setPassNeed( bool bVal )
{
    mUsePassCheck->setChecked( bVal );
    checkUsePasswd();

    if( bVal == true )
        mUsePassCheck->hide();
    else
        mUsePassCheck->show();
}

void SetPassDlg::initialize()
{
    checkUsePasswd();
}

void SetPassDlg::initUI()
{
    mUsePassCheck->setChecked( true );
}

void SetPassDlg::checkUsePasswd()
{
    bool bVal = mUsePassCheck->isChecked();

    if( bVal == true )
        mDescLabel->setText( tr("Please enter password, that will be used to encrypt private keys") );
    else
        mDescLabel->setText( tr("It is set to be unsafe") );

    mPasswdLabel->setEnabled( bVal );
    mPasswdText->setEnabled( bVal );
    mPasswdConfirmLabel->setEnabled( bVal );
    mPasswdConfirmText->setEnabled( bVal );
}

void SetPassDlg::accept()
{
    if( mUsePassCheck->isChecked() == false )
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
