/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef CERT_INFO_DLG_H
#define CERT_INFO_DLG_H

#include <QDialog>
#include "ui_cert_info_dlg.h"


namespace Ui {
class CertInfoDlg;
}

class CertRec;

class CertInfoDlg : public QDialog, public Ui::CertInfoDlg
{
    Q_OBJECT

public:
    explicit CertInfoDlg(QWidget *parent = nullptr);
    ~CertInfoDlg();

    int getCertNum() { return cert_num_; };
    void setCertNum( int cert_num );
    QTableWidgetItem* getExtNameItem( const QString strSN );

private slots:
    void showEvent(QShowEvent *event);
    void clickField( QModelIndex index );
    void clickCheck();
    void clickViewPubKey();
    void clickVerifyCert();
    void clickPathValidation();

    void changeFieldType( int index );

private:
    int cert_num_;
    QList<CertRec> cert_list_;

    void getFields();
    void pathInit();
    void initUI();
    void clearTable();
};

#endif // CERT_INFO_DLG_H
