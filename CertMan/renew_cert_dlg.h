#ifndef RENEW_CERT_DLG_H
#define RENEW_CERT_DLG_H

#include <QDialog>
#include "ui_renew_cert_dlg.h"
#include "js_bin.h"

namespace Ui {
class RenewCertDlg;
}

class RenewCertDlg : public QDialog, public Ui::RenewCertDlg
{
    Q_OBJECT

public:
    explicit RenewCertDlg(QWidget *parent = nullptr);
    ~RenewCertDlg();

    void setCertNum( int cert_num );

private slots:
    virtual void accept();
    void showEvent(QShowEvent *event);

    void changeDayType( int index );
    void clickUseDay();
    void clickKeepSerial();
    void clickRevoke();

private:
    void initialize();

    int cert_num_;
    bool is_self_;
};

#endif // RENEW_CERT_DLG_H
