#ifndef USER_DLG_H
#define USER_DLG_H

#include <QDialog>
#include "ui_user_dlg.h"

namespace Ui {
class UserDlg;
}

class UserDlg : public QDialog, public Ui::UserDlg
{
    Q_OBJECT

public:
    explicit UserDlg(QWidget *parent = nullptr);
    ~UserDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void getRefCode();
    void getSecretNum();
private:
    void initUI();
    void initialize();
};

#endif // USER_DLG_H