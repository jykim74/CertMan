#include "make_cert_policy_dlg.h"
#include "ui_make_cert_policy_dlg.h"

MakeCertPolicyDlg::MakeCertPolicyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MakeCertPolicyDlg)
{
    ui->setupUi(this);
}

MakeCertPolicyDlg::~MakeCertPolicyDlg()
{
    delete ui;
}
