#ifndef MAKE_CRL_PROFILE_DLG_H
#define MAKE_CRL_PROFILE_DLG_H

#include <QDialog>
#include "ui_make_crl_profile_dlg.h"

class ProfileExtRec;

namespace Ui {
class MakeCRLProfileDlg;
}

class MakeCRLProfileDlg : public QDialog, public Ui::MakeCRLProfileDlg
{
    Q_OBJECT

public:
    explicit MakeCRLProfileDlg(QWidget *parent = nullptr);
    ~MakeCRLProfileDlg();

    void setEdit( int nProfileNum );
    bool isEdit() { return is_edit_; };
    int profileNum() { return profile_num_; };

    void loadProfile( int nProfileNum, bool bCopy = false );

private slots:
    virtual void accept();

    void slotIANMenuRequested(QPoint pos);
    void slotIDPMenuRequested(QPoint pos);
    void deleteIANMenu();
    void deleteIDPMenu();

    void slotExtensionsMenuRequested(QPoint pos);
    void deleteExtensionsMenu();

    void clickUseFromNow();
    void clickCRLNum();
    void clickAKI();
    void clickIDP();
    void clickIAN();
    void clickExtensionsUse();

    void addIDP();
    void addIAN();
    void addExtensions();

    void clearIDP();
    void clearIAN();
    void clearExtensions();


private:
    void initUI();
    void connectExtends();
    void setExtends();
    void setTableMenus();

    void saveCRLNumUse( int nProfileNum );
    void saveAKIUse( int nProfileNum );
    void saveIDPUse( int nProfileNum );
    void saveIANUse( int nProfileNum );
    void saveExtensionsUse( int nProfileNum );

    void setCRLNumUse( ProfileExtRec& profileRec );
    void setAKIUse( ProfileExtRec& profileRec );
    void setIDPUse( ProfileExtRec& profileRec );
    void setIANUse( ProfileExtRec& profileRec );
    void setExtensionsUse( ProfileExtRec& profileRec );

    void initialize();

    void defaultProfile();

    bool is_edit_;
    int profile_num_;
};

#endif // MAKE_CRL_PROFILE_DLG_H
