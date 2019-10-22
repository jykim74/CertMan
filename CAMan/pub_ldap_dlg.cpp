#include "pub_ldap_dlg.h"
#include "ui_pub_ldap_dlg.h"

PubLDAPDlg::PubLDAPDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PubLDAPDlg)
{
    ui->setupUi(this);
}

PubLDAPDlg::~PubLDAPDlg()
{
    delete ui;
}
