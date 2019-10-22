#ifndef IMPORT_CRL_DLG_H
#define IMPORT_CRL_DLG_H

#include <QDialog>

namespace Ui {
class ImportCRLDlg;
}

class ImportCRLDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportCRLDlg(QWidget *parent = nullptr);
    ~ImportCRLDlg();

private:
    Ui::ImportCRLDlg *ui;
};

#endif // IMPORT_CRL_DLG_H
