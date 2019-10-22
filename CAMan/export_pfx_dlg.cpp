#include "export_pfx_dlg.h"
#include "ui_export_pfx_dlg.h"

ExportPFXDlg::ExportPFXDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportPFXDlg)
{
    ui->setupUi(this);
}

ExportPFXDlg::~ExportPFXDlg()
{
    delete ui;
}
