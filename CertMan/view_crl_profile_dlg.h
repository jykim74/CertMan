#ifndef VIEW_CRL_PROFILE_DLG_H
#define VIEW_CRL_PROFILE_DLG_H

#include <QDialog>
#include "ui_view_crl_profile_dlg.h"

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
    int profile_num_;
};

#endif // VIEW_CRL_PROFILE_DLG_H
