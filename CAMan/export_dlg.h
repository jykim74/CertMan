#ifndef EXPORT_DLG_H
#define EXPORT_DLG_H

#include <QDialog>
#include "ui_export_dlg.h"

namespace Ui {
class ExportDlg;
}

enum {
    DATA_TYPE_PRIKEY = 1,
    DATA_TYPE_ENC_PRIKEY,
    DATA_TYPE_PUBKEY,
    DATA_TYPE_REQUEST,
    DATA_TYPE_CERTIFICATE,
    DATA_TYPE_CRL,
    DATA_TYPE_PFX
};

class ExportDlg : public QDialog, public Ui::ExportDlg
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();
    int dataType() { return data_type_; };
    int dataNum() { return data_num_; };

    void setDataType( int data_type );
    void setDataNum( int data_num );

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void clickFind();

private:
    void initUI();
    void initialize();

private:
    int data_type_;
    int data_num_;
};

#endif // EXPORT_DLG_H
