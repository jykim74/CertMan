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
        manApplet->warningBox( tr("Insert Password"), this );
        return;
    }

    QString strHMAC = getPasswdHMAC( strPasswd );

    if( strConf != strHMAC )
    {
        manApplet->warningBox( tr("Password is wrong"), this );
        return;
    }

    manApplet->setPasswdKey( strPasswd );
    return QDialog::accept();
}
