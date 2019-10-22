#include "import_crl_dlg.h"
#include "ui_import_crl_dlg.h"

ImportCRLDlg::ImportCRLDlg(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportCRLDlg)
{
    ui->setupUi(this);
}

ImportCRLDlg::~ImportCRLDlg()
{
    delete ui;
}
