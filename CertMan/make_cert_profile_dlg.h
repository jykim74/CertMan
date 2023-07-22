#ifndef MAKE_CERT_PROFILE_DLG_H
#define MAKE_CERT_PROFILE_DLG_H

#include <QDialog>
#include "ui_make_cert_profile_dlg.h"

class ProfileExtRec;

namespace Ui {
class MakeCertProfileDlg;
}

class MakeCertProfileDlg : public QDialog, public Ui::MakeCertProfileDlg
{
    Q_OBJECT

public:
    explicit MakeCertProfileDlg(QWidget *parent = nullptr);
    ~MakeCertProfileDlg();
    void setEdit( int nProfileNum );
    bool isEdit() { return is_edit_; };
    int profileNum() { return profile_num_; };
    void loadProfile( int nProfileNum, bool bCopy = false );

private slots:
    virtual void accept();
    void changeDaysType( int index );

    void slotKeyUsageMenuRequested(QPoint pos);
    void deleteKeyUsageMenu();

    void slotEKUMenuRequested(QPoint pos);
    void deleteEKUMenu();

    void slotPolicyMenuRequested(QPoint pos);
    void deletePolicyMenu();

    void slotCRLDPMenuRequested(QPoint pos);
    void deleteCRLDPMenu();

    void slotAIAMenuRequested(QPoint pos);
    void deleteAIAMenu();

    void slotSANMenuRequested(QPoint pos);
    void deleteSANMenu();

    void slotIANMenuRequested(QPoint pos);
    void deleteIANMenu();

    void slotPMMenuRequested(QPoint pos);
    void deletePMMenu();

    void slotNCMenuRequested(QPoint pos);
    void deleteNCMenu();

    void slotExtensionsMenuRequested(QPoint pos);
    void deleteExtensionsMenu();

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
    void addExtensions();

    void clearKeyUsage();
    void clearPolicy();
    void clearEKU();
    void clearCRLDP();
    void clearAIA();
    void clearSAN();
    void clearIAN();
    void clearPM();
    void clearNC();
    void clearExtensions();

    void clickPolicySetAnyOID();
    void checkForCSR();
private:
    void initUI();
    void connectExtends();
    void setExtends();
    void setTableMenus();

    void saveAIAUse( int nProfileNum );
    void saveAKIUse(int nProfileNum );
    void saveBCUse(int nProfileNum );
    void saveCRLDPUse(int nProfileNum );
    void saveEKUUse(int nProfileNum );
    void saveIANUse(int nProfileNum );
    void saveKeyUsageUse(int nProfileNum );
    void saveNCUse(int nProfileNum );
    void savePolicyUse(int nProfileNum );
    void savePCUse(int nProfileNum );
    void savePMUse(int nProfileNum );
    void saveSKIUse(int nProfileNum );
    void saveSANUse(int nProfileNum );
    void saveExtensionsUse( int nProfileNum );


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

    void initialize();

    void defaultProfile();

    bool is_edit_;
    int profile_num_;
    QList<QString> ext_rmlist_;
};

#endif // MAKE_CERT_PROFILE_DLG_H
