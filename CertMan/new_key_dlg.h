/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef NEW_KEY_DLG_H
#define NEW_KEY_DLG_H

#include <QDialog>
#include "ui_new_key_dlg.h"
#include "js_bin.h"

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
    virtual void accept();
//    void mechChanged(int index);

    void clickRSA();
    void clickECDSA();
    void clickDSA();
    void clickEdDSA();

    void checkPKCS11();
    void checkKMIP();

private:
    void initUI();
    void initialize();
    const QString getMechanism();
};

#endif // NEW_KEY_DLG_H
