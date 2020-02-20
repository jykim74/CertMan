#ifndef MAKE_CRL_DLG_H
#define MAKE_CRL_DLG_H

#include <QDialog>
#include "ui_make_crl_dlg.h"

class CertRec;
class CRLPolicyRec;

namespace Ui {
class MakeCRLDlg;
}

class MakeCRLDlg : public QDialog, public Ui::MakeCRLDlg
{
    Q_OBJECT

public:
    explicit MakeCRLDlg(QWidget *parent = nullptr);
    ~MakeCRLDlg();
    void setFixIssuer( QString strIssuerName );

private slots:
    virtual void accept();
    void issuerChanged(int index);
    void clickRevokeAdd();


private:
    void initialize();
    void setRevokeList();

    QList<CertRec> ca_cert_list_;
    QList<CRLPolicyRec> crl_policy_list_;
;
};

#endif // MAKE_CRL_DLG_H
