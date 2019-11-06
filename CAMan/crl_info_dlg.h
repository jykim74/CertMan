#ifndef CRL_INFO_DLG_H
#define CRL_INFO_DLG_H

#include <QDialog>
#include "ui_crl_info_dlg.h"
#include "js_bin.h"
#include "js_pki_x509.h"

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
    void clickCRLField( QModelIndex index );
    void clickRevokeField( QModelIndex index );

private:
    int crl_num_;
    void initialize();
    void initUI();
    void clearTable();

    JSCRLInfo crl_info_;
    JSExtensionInfoList* ext_info_list_;
    JSRevokeInfoList* revoke_info_list_;
};

#endif // CRL_INFO_DLG_H