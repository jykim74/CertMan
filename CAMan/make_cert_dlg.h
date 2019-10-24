#ifndef MAKE_CERT_DLG_H
#define MAKE_CERT_DLG_H

#include <QDialog>
#include "ui_make_cert_dlg.h"

class ReqRec;
class CertRec;
class CertPolicyRec;

namespace Ui {
class MakeCertDlg;
}

class MakeCertDlg : public QDialog, public Ui::MakeCertDlg
{
    Q_OBJECT

public:
    explicit MakeCertDlg(QWidget *parent = nullptr);
    ~MakeCertDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void reqChanged( int index );
    void issuerChanged( int index );
    void clickSelfSign();

private:
    QList<ReqRec>           req_list_;
    QList<CertRec>          ca_cert_list_;
    QList<CertPolicyRec>    cert_policy_list_;

    void initialize();
};

#endif // MAKE_CERT_DLG_H
