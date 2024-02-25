/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef PIN_DLG_H
#define PIN_DLG_H

#include <QDialog>
#include "ui_pin_dlg.h"

namespace Ui {
class PinDlg;
}

class PinDlg : public QDialog, public Ui::PinDlg
{
    Q_OBJECT

public:
    explicit PinDlg(QWidget *parent = nullptr);
    ~PinDlg();

    QString getPinText() { return mPinText->text(); };

private:

};

#endif // PIN_DLG_H
