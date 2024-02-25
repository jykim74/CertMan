/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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

    void getRefNum();
    void getAuthCode();
    void regServer();

private:
    void initUI();
    void initialize();

};

#endif // USER_DLG_H
