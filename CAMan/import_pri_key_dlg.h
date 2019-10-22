#ifndef IMPORT_PRI_KEY_DLG_H
#define IMPORT_PRI_KEY_DLG_H

#include <QDialog>

namespace Ui {
class ImportPriKeyDlg;
}

class ImportPriKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportPriKeyDlg(QWidget *parent = nullptr);
    ~ImportPriKeyDlg();

private:
    Ui::ImportPriKeyDlg *ui;
};

#endif // IMPORT_PRI_KEY_DLG_H
