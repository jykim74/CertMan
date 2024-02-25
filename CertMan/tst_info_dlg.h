/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef TST_INFO_DLG_H
#define TST_INFO_DLG_H

#include <QDialog>
#include "ui_tst_info_dlg.h"
#include "js_bin.h"

namespace Ui {
class TSTInfoDlg;
}

class TSTInfoDlg : public QDialog, public Ui::TSTInfoDlg
{
    Q_OBJECT

public:
    explicit TSTInfoDlg(QWidget *parent = nullptr);
    ~TSTInfoDlg();
    void setTST( const BIN *pTST );

private slots:
    void showEvent(QShowEvent *event);

private:
    BIN bin_tst_;
    void initialize();
    void initUI();
    void clearTable();
};

#endif // TST_INFO_DLG_H
