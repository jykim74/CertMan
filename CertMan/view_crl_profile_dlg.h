#ifndef VIEW_CRL_PROFILE_DLG_H
#define VIEW_CRL_PROFILE_DLG_H

#include <QDialog>
#include "ui_view_crl_profile_dlg.h"

class ProfileExtRec;

namespace Ui {
class ViewCRLProfileDlg;
}

class ViewCRLProfileDlg : public QDialog, public Ui::ViewCRLProfileDlg
{
    Q_OBJECT

public:
    explicit ViewCRLProfileDlg(QWidget *parent = nullptr);
    ~ViewCRLProfileDlg();

    int setProfile( int nNum );

private:
    void initUI();
    void initialize();

    void setCRLNumUse( ProfileExtRec& profileRec );
    void setAKIUse( ProfileExtRec& profileRec );
    void setIDPUse( ProfileExtRec& profileRec );
    void setIANUse( ProfileExtRec& profileRec );
    void setExtensionsUse( ProfileExtRec& profileRec );

    int profile_num_;
};

#endif // VIEW_CRL_PROFILE_DLG_H
