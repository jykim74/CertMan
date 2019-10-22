#ifndef MAKE_CERT_POLICY_DLG_H
#define MAKE_CERT_POLICY_DLG_H

#include <QDialog>

namespace Ui {
class MakeCertPolicyDlg;
}

class MakeCertPolicyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit MakeCertPolicyDlg(QWidget *parent = nullptr);
    ~MakeCertPolicyDlg();

private:
    Ui::MakeCertPolicyDlg *ui;
};

#endif // MAKE_CERT_POLICY_DLG_H
