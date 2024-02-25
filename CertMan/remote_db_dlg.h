/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef REMOTE_DB_DLG_H
#define REMOTE_DB_DLG_H

#include <QDialog>
#include "ui_remote_db_dlg.h"

namespace Ui {
class RemoteDBDlg;
}

class RemoteDBDlg : public QDialog, public Ui::RemoteDBDlg
{
    Q_OBJECT

public:
    explicit RemoteDBDlg(QWidget *parent = nullptr);
    ~RemoteDBDlg();

private slots:
    void clickClear();
    void clickConnect();

private:
    void initialize();
};

#endif // REMOTE_DB_DLG_H
