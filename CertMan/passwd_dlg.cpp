#include "passwd_dlg.h"
#include "ui_passwd_dlg.h"
#include "commons.h"
#include "man_applet.h"

PasswdDlg::PasswdDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PasswdDlg::~PasswdDlg()
{

}

void PasswdDlg::setTitle( const QString strTitle )
{
    mTitleLabel->setText( strTitle );
}

void PasswdDlg::clickOK()
{
    QString strPasswd = mPasswdText->text();

    if( strPasswd.length() < 1 )
    {
        manApplet->warningBox( tr("Enter a password" ), this );
        return;
    }

    QDialog::accept();
}
