#include "login_dlg.h"

LoginDlg::LoginDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    mPasswdText->setFocus();
}

LoginDlg::~LoginDlg()
{

}

void LoginDlg::accept()
{
    return QDialog::accept();
}
