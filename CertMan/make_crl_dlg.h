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
    void setFixIssuer( QString strIssuerName );

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);
    void issuerChanged(int index);
    void crldpChanged(int index);


private:
    void initialize();
    void setRevokeList();

    QList<CertRec> ca_cert_list_;
    QList<CRLProfileRec> crl_profile_list_;
};

#endif // MAKE_CRL_DLG_H
