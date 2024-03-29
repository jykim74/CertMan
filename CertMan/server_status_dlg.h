/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SERVER_STATUS_DLG_H
#define SERVER_STATUS_DLG_H

#include <QDialog>
#include "ui_server_status_dlg.h"

namespace Ui {
class ServerStatusDlg;
}

class ServerStatusDlg : public QDialog, public Ui::ServerStatusDlg
{
    Q_OBJECT

public:
    explicit ServerStatusDlg(QWidget *parent = nullptr);
    ~ServerStatusDlg();

private slots:
    void refreshStatus();
    void refresh();

private:
    Q_DISABLE_COPY(ServerStatusDlg)
};

#endif // SERVER_STATUS_DLG_H
