#ifndef MAKE_REQ_DLG_H
#define MAKE_REQ_DLG_H

#include <QDialog>
#include <QList>
#include "ui_make_req_dlg.h"

class KeyPairRec;

namespace Ui {
class MakeReqDlg;
}

class MakeReqDlg : public QDialog, public Ui::MakeReqDlg
{
    Q_OBJECT

public:
    explicit MakeReqDlg(QWidget *parent = nullptr);
    ~MakeReqDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void keyNameChanged(int index);


private:
    void initUI();
    void initialize();

    QList<KeyPairRec> key_list_;

};

#endif // MAKE_REQ_DLG_H
