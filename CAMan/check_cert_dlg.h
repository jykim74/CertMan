#ifndef CHECK_CERT_DLG_H
#define CHECK_CERT_DLG_H

#include <QDialog>
#include "ui_check_cert_dlg.h"

class CertRec;

namespace Ui {
class CheckCertDlg;
}

class CheckCertDlg : public QDialog, public Ui::CheckCertDlg
{
    Q_OBJECT

public:
    explicit CheckCertDlg(QWidget *parent = nullptr);
    ~CheckCertDlg();
    int certNum() { return cert_num_; };
    void setCertNum( int cert_num );

private slots:
    void clickClose();
    void clickView();
    void clickCheck();

private:
    int cert_num_;
    QList<CertRec> cert_list_;

    void initUI();
    void initialize();
};

#endif // CHECK_CERT_DLG_H
