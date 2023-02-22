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
    void clickCRLField( QModelIndex index );
    void clickRevokeField( QModelIndex index );
    void showEvent(QShowEvent *event);
    void clickVerifyCRL();

private:
    int crl_num_;
    void initialize();
    void initUI();
    void clearTable();

    JCRLInfo crl_info_;
    JExtensionInfoList* ext_info_list_;
    JRevokeInfoList* revoke_info_list_;
};

#endif // CRL_INFO_DLG_H
