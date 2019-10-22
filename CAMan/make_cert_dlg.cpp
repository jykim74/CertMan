#include "make_cert_dlg.h"
#include "ui_make_cert_dlg.h"

MakeCertDlg::MakeCertDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MakeCertDlg)
{
    ui->setupUi(this);
}

MakeCertDlg::~MakeCertDlg()
{
    delete ui;
}
