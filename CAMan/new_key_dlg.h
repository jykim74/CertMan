#ifndef NEW_KEY_DLG_H
#define NEW_KEY_DLG_H

#include <QDialog>
#include "ui_new_key_dlg.h"

namespace Ui {
class NewKeyDlg;
}

class NewKeyDlg : public QDialog, public Ui::NewKeyDlg
{
    Q_OBJECT

public:
    explicit NewKeyDlg(QWidget *parent = nullptr);
    ~NewKeyDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void mechChanged(int index);


private:
    void initUI();

};

#endif // NEW_KEY_DLG_H
