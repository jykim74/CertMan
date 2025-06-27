#ifndef VIEW_CERT_PROFILE_DLG_H
#define VIEW_CERT_PROFILE_DLG_H

#include <QDialog>
#include "ui_view_cert_profile_dlg.h"

class ProfileExtRec;

namespace Ui {
class ViewCertProfileDlg;
}

class ViewCertProfileDlg : public QDialog, public Ui::ViewCertProfileDlg
{
    Q_OBJECT

public:
    explicit ViewCertProfileDlg(QWidget *parent = nullptr);
    ~ViewCertProfileDlg();

    int setProfile( int nNum );

private:
    void initUI();
    void initialize();

    void setAIAUse( ProfileExtRec& profileRec );
    void setAKIUse( ProfileExtRec& profileRec );
    void setBCUse( ProfileExtRec& profileRec );
    void setCRLDPUse( ProfileExtRec& profileRec );
    void setEKUUse( ProfileExtRec& profileRec );
    void setIANUse( ProfileExtRec& profileRec );
    void setKeyUsageUse( ProfileExtRec& profileRec );
    void setNCUse( ProfileExtRec& profileRec );
    void setPolicyUse( ProfileExtRec& profileRec );
    void setPCUse( ProfileExtRec& profileRec );
    void setPMUse( ProfileExtRec& profileRec );
    void setSKIUse( ProfileExtRec& profileRec );
    void setSANUse( ProfileExtRec& profileRec );
    void setExtensionsUse( ProfileExtRec& profileRec );

    int profile_num_;
};

#endif // VIEW_CERT_PROFILE_DLG_H
