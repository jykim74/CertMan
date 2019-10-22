#include "make_crl_policy_dlg.h"
#include "ui_make_crl_policy_dlg.h"

MakeCRLPolicyDlg::MakeCRLPolicyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MakeCRLPolicyDlg)
{
    ui->setupUi(this);
}

MakeCRLPolicyDlg::~MakeCRLPolicyDlg()
{
    delete ui;
}
