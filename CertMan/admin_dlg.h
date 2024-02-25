/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef ADMIN_DLG_H
#define ADMIN_DLG_H

#include <QDialog>
#include "ui_admin_dlg.h"

namespace Ui {
class AdminDlg;
}

class AdminDlg : public QDialog, public Ui::AdminDlg
{
    Q_OBJECT

public:
    explicit AdminDlg(QWidget *parent = nullptr);
    ~AdminDlg();
    void setEditMode( bool bVal );
    void setSeq( int nSeq );
    void showEvent(QShowEvent *event);

private slots:
    void clickClose();
    void clickRegister();
    void clickDelete();
    void clickModify();

private:
    void initialize();

    bool    edit_mode_;
    int    seq_;
};

#endif // ADMIN_DLG_H
