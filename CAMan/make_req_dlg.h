#ifndef MAKE_REQ_DLG_H
#define MAKE_REQ_DLG_H

#include <QDialog>
#include "ui_make_req_dlg.h"

namespace Ui {
class MakeReqDlg;
}

class MakeReqDlg : public QDialog, public Ui::MakeReqDlg
{
    Q_OBJECT

public:
    explicit MakeReqDlg(QWidget *parent = nullptr);
    ~MakeReqDlg();

private:

};

#endif // MAKE_REQ_DLG_H
