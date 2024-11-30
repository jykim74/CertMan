/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAKE_CERT_DLG_H
#define MAKE_CERT_DLG_H

#include <QDialog>
#include "ui_make_cert_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"

class ReqRec;
class CertRec;
class CertProfileRec;
class ProfileExtRec;

namespace Ui {
class MakeCertDlg;
}

class MakeCertDlg : public QDialog, public Ui::MakeCertDlg
{
    Q_OBJECT

public:
    explicit MakeCertDlg(QWidget *parent = nullptr);
    ~MakeCertDlg();
    void setIssuer( int nCertNum );
    void setReqNum( int nReqNum );

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);
    void reqNumChanged();
    void issuerNumChanged();
    void profileNumChanged();
    void clickSelfSign();
    void clickUseCSRFile();
    void findCSRFile();
    void clickMakeDN();

    void clickSelectCSR();
    void clickSelectProfile();
    void clickSelectCACert();

private:
    void initialize();
    void setSubjectDN();
    QString getRealSubjectDN();
    QString getReplacedValue( QString &strVal );
};

#endif // MAKE_CERT_DLG_H
