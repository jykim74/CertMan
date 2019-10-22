#include "export_cert_dlg.h"
#include "ui_export_cert_dlg.h"

ExportCertDlg::ExportCertDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportCertDlg)
{
    ui->setupUi(this);
}

ExportCertDlg::~ExportCertDlg()
{
    delete ui;
}
