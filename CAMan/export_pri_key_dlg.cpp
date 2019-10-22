#include "export_pri_key_dlg.h"
#include "ui_export_pri_key_dlg.h"

ExportPriKeyDlg::ExportPriKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportPriKeyDlg)
{
    ui->setupUi(this);
}

ExportPriKeyDlg::~ExportPriKeyDlg()
{
    delete ui;
}
