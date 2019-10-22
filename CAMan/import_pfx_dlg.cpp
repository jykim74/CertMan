#include "import_pfx_dlg.h"
#include "ui_import_pfx_dlg.h"

ImportPFXDlg::ImportPFXDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportPFXDlg)
{
    ui->setupUi(this);
}

ImportPFXDlg::~ImportPFXDlg()
{
    delete ui;
}
