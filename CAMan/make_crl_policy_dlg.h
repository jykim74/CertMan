#ifndef MAKE_CRL_POLICY_DLG_H
#define MAKE_CRL_POLICY_DLG_H

#include <QDialog>
#include "ui_make_crl_policy_dlg.h"

namespace Ui {
class MakeCRLPolicyDlg;
}

class MakeCRLPolicyDlg : public QDialog, public Ui::MakeCRLPolicyDlg
{
    Q_OBJECT

public:
    explicit MakeCRLPolicyDlg(QWidget *parent = nullptr);
    ~MakeCRLPolicyDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void clickCRLNum();
    void clickAKI();
    void clickDPN();
    void clickIAN();

    void addDPN();
    void addIAN();


private:
    void initUI();
    void connectExtends();
    void setExtends();
    void setTableMenus();
};

#endif // MAKE_CRL_POLICY_DLG_H
