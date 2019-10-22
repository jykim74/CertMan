#ifndef IMPORT_PFX_DLG_H
#define IMPORT_PFX_DLG_H

#include <QDialog>

namespace Ui {
class ImportPFXDlg;
}

class ImportPFXDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportPFXDlg(QWidget *parent = nullptr);
    ~ImportPFXDlg();

private:
    Ui::ImportPFXDlg *ui;
};

#endif // IMPORT_PFX_DLG_H
