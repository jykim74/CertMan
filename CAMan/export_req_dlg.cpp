#include "export_req_dlg.h"
#include "ui_export_req_dlg.h"

ExportReqDlg::ExportReqDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ExportReqDlg)
{
    ui->setupUi(this);
}

ExportReqDlg::~ExportReqDlg()
{
    delete ui;
}
