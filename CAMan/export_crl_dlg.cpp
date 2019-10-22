#include "export_crl_dlg.h"
#include "ui_export_crl_dlg.h"

ExportCRLDlg::ExportCRLDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportCRLDlg)
{
    ui->setupUi(this);
}

ExportCRLDlg::~ExportCRLDlg()
{
    delete ui;
}
