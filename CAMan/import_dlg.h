#ifndef IMPORT_DLG_H
#define IMPORT_DLG_H

#include <QDialog>

namespace Ui {
class ImportDlg;
}

class ImportDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportDlg(QWidget *parent = nullptr);
    ~ImportDlg();

private:
    Ui::ImportDlg *ui;
};

#endif // IMPORT_DLG_H
