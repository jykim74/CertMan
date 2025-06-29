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

    void setAIAEnable( bool bVal );
    void setAKIEnable( bool bVal );
    void setBCEnable( bool bVal );
    void setCRLDPEnable( bool bVal );
    void setEKUEnable( bool bVal );
    void setIANEnable( bool bVal );
    void setKeyUsageEnable( bool bVal );
    void setNCEnable( bool bVal );
    void setPolicyEnable( bool bVal );
    void setPCEnable( bool bVal );
    void setPMEnable( bool bVal );
    void setSKIEnable( bool bVal );
    void setSANEnable( bool bVal );
    void setExtensionsEnable( bool bVal );
    void setAllEnable( bool bVal );

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
