#include "login_dlg.h"

LoginDlg::LoginDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
}

LoginDlg::~LoginDlg()
{

}

void LoginDlg::accept()
{
    return QDialog::accept();
}