#include "import_cert_dlg.h"
#include "ui_import_cert_dlg.h"

ImportCertDlg::ImportCertDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportCertDlg)
{
    ui->setupUi(this);
}

ImportCertDlg::~ImportCertDlg()
{
    delete ui;
}
