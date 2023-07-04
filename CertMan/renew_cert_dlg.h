#ifndef RENEW_CERT_DLG_H
#define RENEW_CERT_DLG_H

#include <QDialog>
#include "ui_renew_cert_dlg.h"

namespace Ui {
class RenewCertDlg;
}

class RenewCertDlg : public QDialog, public Ui::RenewCertDlg
{
    Q_OBJECT

public:
    explicit RenewCertDlg(QWidget *parent = nullptr);
    ~RenewCertDlg();

private:

};

#endif // RENEW_CERT_DLG_H
