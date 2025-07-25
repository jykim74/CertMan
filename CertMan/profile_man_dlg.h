#ifndef PROFILE_MAN_DLG_H
#define PROFILE_MAN_DLG_H

#include <QDialog>
#include "ui_profile_man_dlg.h"

enum {
    ProfileManModeManage = 0,
    ProfileManModeSelectCertProfile,
    ProfileManModeSelectCSRProfile,
    ProfileManModeSelectCRLProfile
};

namespace Ui {
class ProfileManDlg;
}

class ProfileManDlg : public QDialog, public Ui::ProfileManDlg
{
    Q_OBJECT

public:
    explicit ProfileManDlg(QWidget *parent = nullptr);
    ~ProfileManDlg();

    void setMode( int nMode );
    void setTitle( const QString strTitle );
    int getNum() { return num_; };

private slots:
    void showEvent(QShowEvent *event);
    void changeTab( int index );

    void slotCertTableMenuRequested( QPoint pos );
    void slotCRLTableMenuRequested( QPoint pos );

    void clickOK();

    void loadCertProfileList();
    void loadCRLProfileList();

    void clickCertProfileView();
    void clickCertProfileDelete();

    void clickCRLProfileView();
    void clickCRLProfileDelete();

private:
    void initUI();
    void initialize();

    int num_;
};

#endif // PROFILE_MAN_DLG_H
