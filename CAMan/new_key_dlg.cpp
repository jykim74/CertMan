#include "new_key_dlg.h"
#include "ui_new_key_dlg.h"

NewKeyDlg::NewKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::NewKeyDlg)
{
    ui->setupUi(this);
}

NewKeyDlg::~NewKeyDlg()
{
    delete ui;
}
