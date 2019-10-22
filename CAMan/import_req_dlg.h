#ifndef IMPORT_REQ_DLG_H
#define IMPORT_REQ_DLG_H

#include <QDialog>

namespace Ui {
class ImportReqDlg;
}

class ImportReqDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ImportReqDlg(QWidget *parent = nullptr);
    ~ImportReqDlg();

private:
    Ui::ImportReqDlg *ui;
};

#endif // IMPORT_REQ_DLG_H
