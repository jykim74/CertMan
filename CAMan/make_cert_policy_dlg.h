#ifndef MAKE_CERT_POLICY_DLG_H
#define MAKE_CERT_POLICY_DLG_H

#include <QDialog>
#include "ui_make_cert_policy_dlg.h"

namespace Ui {
class MakeCertPolicyDlg;
}

class MakeCertPolicyDlg : public QDialog, public Ui::MakeCertPolicyDlg
{
    Q_OBJECT

public:
    explicit MakeCertPolicyDlg(QWidget *parent = nullptr);
    ~MakeCertPolicyDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void clickUseCSR();
    void clickUseDays();

    void clickAIAUse();
    void clickAKIUse();
    void clickBCUse();
    void clickCRLDPUse();
    void clickEKUUse();
    void clickIANUse();
    void clickKeyUsageUse();
    void clickNCUse();
    void clickPolicyUse();
    void clickPCUse();
    void clickPMUse();
    void clickSKIUse();
    void clickSANUse();

    void addKeyUsage();
    void addPolicy();
    void addEKU();
    void addCRLDP();
    void addAIA();
    void addSAN();
    void addIAN();
    void addPM();
    void addNC();


private:
    void initUI();
    void connectExtends();
    void setExtends();
    void setTableMenus();

    void setAIAUse( int nPolicyNum );
    void setAKIUse(int nPolicyNum );
    void setBCUse(int nPolicyNum );
    void setCRLDPUse(int nPolicyNum );
    void setEKUUse(int nPolicyNum );
    void setIANUse(int nPolicyNum );
    void setKeyUsageUse(int nPolicyNum );
    void setNCUse(int nPolicyNum );
    void setPolicyUse(int nPolicyNum );
    void setPCUse(int nPolicyNum );
    void setPMUse(int nPolicyNum );
    void setSKIUse(int nPolicyNum );
    void setSANUse(int nPolicyNum );
};

#endif // MAKE_CERT_POLICY_DLG_H
