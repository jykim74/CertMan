/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAKE_REQ_DLG_H
#define MAKE_REQ_DLG_H

#include <QDialog>
#include <QList>
#include "ui_make_req_dlg.h"

class KeyPairRec;
class CertProfileRec;

namespace Ui {
class MakeReqDlg;
}

class MakeReqDlg : public QDialog, public Ui::MakeReqDlg
{
    Q_OBJECT

public:
    explicit MakeReqDlg(QWidget *parent = nullptr);
    ~MakeReqDlg();

    void setKeyNum( int nKeyNum );

private slots:
    virtual void accept();
    void keyNumChanged();
    void profileNumChanged();
    void newOptionChanged(int index );
    void checkGenKeyPair();
    void checkExtension();
    void clickMakeDN();

    void clickRSA();
    void clickECDSA();
    void clickDSA();
    void clickEdDSA();
    void clickSM2();

    void checkPKCS11();
    void checkKMIP();

    void clickSelectKeyPair();
    void clickSelectProfile();

private:
    void initUI();
    void initialize();
    int genKeyPair( KeyPairRec& keyPair );
    const QString getMechanism();
};

#endif // MAKE_REQ_DLG_H
