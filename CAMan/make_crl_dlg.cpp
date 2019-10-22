#include "make_crl_dlg.h"
#include "ui_make_crl_dlg.h"

MakeCRLDlg::MakeCRLDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MakeCRLDlg)
{
    ui->setupUi(this);
}

MakeCRLDlg::~MakeCRLDlg()
{
    delete ui;
}
