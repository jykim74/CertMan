#ifndef IMPORT_CERT_DLG_H
#define IMPORT_CERT_DLG_H

#include <QDialog>

namespace Ui {
class ImportCertDlg;
}

class ImportCertDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportCertDlg(QWidget *parent = nullptr);
    ~ImportCertDlg();

private:
    Ui::ImportCertDlg *ui;
};

#endif // IMPORT_CERT_DLG_H
