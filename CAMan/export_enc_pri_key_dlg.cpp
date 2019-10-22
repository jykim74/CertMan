#include "export_enc_pri_key_dlg.h"
#include "ui_export_enc_pri_key_dlg.h"

ExportEncPriKeyDlg::ExportEncPriKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportEncPriKeyDlg)
{
    ui->setupUi(this);
}

ExportEncPriKeyDlg::~ExportEncPriKeyDlg()
{
    delete ui;
}
