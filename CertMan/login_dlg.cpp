/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "login_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "commons.h"

#include "js_gen.h"

LoginDlg::LoginDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mLoginBtn, SIGNAL(clicked()), this, SLOT(clickLogin()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();

    mLoginBtn->setDefault(true);
    mPasswdText->setFocus();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
}

LoginDlg::~LoginDlg()
{

}

void LoginDlg::initialize()
{

}

void LoginDlg::clickLogin()
{
    QString strConf;
    manApplet->dbMgr()->getConfigValue( JS_GEN_KIND_CERTMAN, "Passwd", strConf );

    if( strConf.length() < 1 ) return QDialog::reject();

    QString strPasswd = mPasswdText->text();
    if( strPasswd.length() < 1 )
    {
        manApplet->warningBox( tr("Plaes enter a assword"), this );
        return;
    }

    QString strHMAC = getPasswdHMAC( strPasswd );

    if( strConf != strHMAC )
    {
        manApplet->warningBox( tr("Password is incorrect"), this );
        return;
    }

    manApplet->setPasswdKey( strPasswd );
    QDialog::accept();
}
