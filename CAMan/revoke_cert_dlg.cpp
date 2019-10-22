#include "revoke_cert_dlg.h"
#include "ui_revoke_cert_dlg.h"

RevokeCertDlg::RevokeCertDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RevokeCertDlg)
{
    ui->setupUi(this);
}

RevokeCertDlg::~RevokeCertDlg()
{
    delete ui;
}
