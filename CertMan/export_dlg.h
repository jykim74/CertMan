/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef EXPORT_DLG_H
#define EXPORT_DLG_H

#include <QDialog>
#include "ui_export_dlg.h"

namespace Ui {
class ExportDlg;
}

enum {
    EXPORT_TYPE_PRIKEY = 1,
    EXPORT_TYPE_ENC_PRIKEY,
    EXPORT_TYPE_PUBKEY,
    EXPORT_TYPE_REQUEST,
    EXPORT_TYPE_CERTIFICATE,
    EXPORT_TYPE_CRL,
    EXPORT_TYPE_PFX
};

class ExportDlg : public QDialog, public Ui::ExportDlg
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();
    int exportType() { return export_type_; };
    int dataNum() { return data_num_; };

    void setExportType( int export_type );
    void setDataNum( int data_num );

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void clickFind();
    void clickPEMSaveCheck();

    void changePBEVersion( int index );

private:
    void initUI();
    void initialize();

private:
    int export_type_;
    int data_num_;
};

#endif // EXPORT_DLG_H
