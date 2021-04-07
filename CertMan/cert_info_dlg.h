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

private slots:
    void showEvent(QShowEvent *event);
    void clickClose();
    void clickField( QModelIndex index );
    void clickCheck();

private:
    int cert_num_;
    QList<CertRec> cert_list_;

    void initialize();
    void pathInit();
    void initUI();
    void clearTable();
};

#endif // CERT_INFO_DLG_H
