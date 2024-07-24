/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "pin_dlg.h"

PinDlg::PinDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

PinDlg::~PinDlg()
{

}
