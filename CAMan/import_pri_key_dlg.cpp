#include "import_pri_key_dlg.h"
#include "ui_import_pri_key_dlg.h"

ImportPriKeyDlg::ImportPriKeyDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportPriKeyDlg)
{
    ui->setupUi(this);
}

ImportPriKeyDlg::~ImportPriKeyDlg()
{
    delete ui;
}
