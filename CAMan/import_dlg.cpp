#include "import_dlg.h"
#include "ui_import_dlg.h"

ImportDlg::ImportDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportDlg)
{
    ui->setupUi(this);
}

ImportDlg::~ImportDlg()
{
    delete ui;
}
