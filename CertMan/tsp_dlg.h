/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef TSP_DLG_H
#define TSP_DLG_H

#include <QDialog>
#include "ui_tsp_dlg.h"

namespace Ui {
class TSPDlg;
}

class TSPDlg : public QDialog, public Ui::TSPDlg
{
    Q_OBJECT

public:
    explicit TSPDlg(QWidget *parent = nullptr);
    ~TSPDlg();

private slots:
    void clickSend();
    void clickClose();
    void clickViewTSTInfo();
    void clickVerifyTSP();

    void changeSrc();
    void changeOutput();

private:
    void initialize();
};

#endif // TSP_DLG_H
