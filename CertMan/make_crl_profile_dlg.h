/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    void setReadOnly();
    bool isEdit() { return is_edit_; };
    int profileNum() { return profile_num_; };

    void loadProfile( int nProfileNum, bool bCopy = false );

private slots:
    void clickOK();
    void changeValidDaysType(int index);

    void slotIANMenuRequested(QPoint pos);
    void slotIDPMenuRequested(QPoint pos);
    void deleteIANMenu();
    void deleteIDPMenu();

    void slotExtensionsMenuRequested(QPoint pos);
    void deleteExtensionsMenu();

    void clickCRLNumAuto();

    void clickUseFromNow();

    void addIDP();
    void addIAN();
    void addExtensions();

    void clearIDP();
    void clearIAN();
    void clearExtensions();


private:
    void initUI();
    void connectExtends();
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
    QList<QString> ext_rmlist_;
};

#endif // MAKE_CRL_PROFILE_DLG_H
