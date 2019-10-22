#ifndef MAKE_CRL_POLICY_DLG_H
#define MAKE_CRL_POLICY_DLG_H

#include <QDialog>

namespace Ui {
class MakeCRLPolicyDlg;
}

class MakeCRLPolicyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit MakeCRLPolicyDlg(QWidget *parent = nullptr);
    ~MakeCRLPolicyDlg();

private:
    Ui::MakeCRLPolicyDlg *ui;
};

#endif // MAKE_CRL_POLICY_DLG_H
