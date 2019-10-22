#ifndef MAKE_REQ_DLG_H
#define MAKE_REQ_DLG_H

#include <QDialog>

namespace Ui {
class MakeReqDlg;
}

class MakeReqDlg : public QDialog
{
    Q_OBJECT

public:
    explicit MakeReqDlg(QWidget *parent = nullptr);
    ~MakeReqDlg();

private:
    Ui::MakeReqDlg *ui;
};

#endif // MAKE_REQ_DLG_H
