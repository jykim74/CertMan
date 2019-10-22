#include "export_dlg.h"
#include "ui_export_dlg.h"

ExportDlg::ExportDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportDlg)
{
    ui->setupUi(this);
}

ExportDlg::~ExportDlg()
{
    delete ui;
}
