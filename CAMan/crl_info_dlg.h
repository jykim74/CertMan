#ifndef CRL_INFO_DLG_H
#define CRL_INFO_DLG_H

#include <QDialog>
#include "ui_crl_info_dlg.h"

namespace Ui {
class CRLInfoDlg;
}

class CRLInfoDlg : public QDialog, public Ui::CRLInfoDlg
{
    Q_OBJECT

public:
    explicit CRLInfoDlg(QWidget *parent = nullptr);
    ~CRLInfoDlg();

    void setCRLNum( int crl_num );
    int getCRLNum() { return crl_num_; };

private slots:
    void showEvent(QShowEvent *event);
    void clickClose();
    void clickField( QModelIndex index );

private:
    int crl_num_;
    void initialize();
    void initUI();
    void clearTable();
};

#endif // CRL_INFO_DLG_H
