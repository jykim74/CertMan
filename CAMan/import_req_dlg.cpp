#include "import_req_dlg.h"
#include "ui_import_req_dlg.h"

ImportReqDlg::ImportReqDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportReqDlg)
{
    ui->setupUi(this);
}

ImportReqDlg::~ImportReqDlg()
{
    delete ui;
}
