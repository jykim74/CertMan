#include "import_enc_pri_key_dlg.h"
#include "ui_import_enc_pri_key_dlg.h"

ImportEncPriKeyDlg::ImportEncPriKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportEncPriKeyDlg)
{
    ui->setupUi(this);
}

ImportEncPriKeyDlg::~ImportEncPriKeyDlg()
{
    delete ui;
}
