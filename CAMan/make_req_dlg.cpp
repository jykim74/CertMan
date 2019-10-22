#include "make_req_dlg.h"
#include "ui_make_req_dlg.h"

MakeReqDlg::MakeReqDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MakeReqDlg)
{
    ui->setupUi(this);
}

MakeReqDlg::~MakeReqDlg()
{
    delete ui;
}
