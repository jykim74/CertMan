/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAKE_CRL_DLG_H
#define MAKE_CRL_DLG_H

#include <QDialog>
#include "ui_make_crl_dlg.h"

class CertRec;
class CRLProfileRec;

namespace Ui {
class MakeCRLDlg;
}

class MakeCRLDlg : public QDialog, public Ui::MakeCRLDlg
{
    Q_OBJECT

public:
    explicit MakeCRLDlg(QWidget *parent = nullptr);
    ~MakeCRLDlg();
    void setIssuerNum( int nIssuerNum );

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);
    void issuerNumChanged();
    void crldpChanged(int index);
    void profileNumChanged();

    void clickSelectIssuer();
    void clickSelectProfile();

private:
    void initUI();
    void initialize();
    void setRevokeList();
};

#endif // MAKE_CRL_DLG_H
