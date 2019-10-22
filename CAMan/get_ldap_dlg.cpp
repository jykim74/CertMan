#include "get_ldap_dlg.h"
#include "ui_get_ldap_dlg.h"

GetLDAPDlg::GetLDAPDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::GetLDAPDlg)
{
    ui->setupUi(this);
}

GetLDAPDlg::~GetLDAPDlg()
{
    delete ui;
}
