#ifndef IMPORT_ENC_PRI_KEY_DLG_H
#define IMPORT_ENC_PRI_KEY_DLG_H

#include <QDialog>

namespace Ui {
class ImportEncPriKeyDlg;
}

class ImportEncPriKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportEncPriKeyDlg(QWidget *parent = nullptr);
    ~ImportEncPriKeyDlg();

private:
    Ui::ImportEncPriKeyDlg *ui;
};

#endif // IMPORT_ENC_PRI_KEY_DLG_H
