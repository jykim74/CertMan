#ifndef REVOKE_CERT_DLG_H
#define REVOKE_CERT_DLG_H

#include <QDialog>
#include "ui_revoke_cert_dlg.h"

namespace Ui {
class RevokeCertDlg;
}

class RevokeCertDlg : public QDialog, public Ui::RevokeCertDlg
{
    Q_OBJECT

public:
    explicit RevokeCertDlg(QWidget *parent = nullptr);
    ~RevokeCertDlg();
    void setCertNum( int cert_num );

private slots:
    virtual void accept();

private:
    void initUI();
    void initialize();

    int cert_num_;
};

#endif // REVOKE_CERT_DLG_H
