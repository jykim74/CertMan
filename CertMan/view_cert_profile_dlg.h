#ifndef VIEW_CERT_PROFILE_DLG_H
#define VIEW_CERT_PROFILE_DLG_H

#include <QDialog>
#include "ui_view_cert_profile_dlg.h"

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
    int profile_num_;
};

#endif // VIEW_CERT_PROFILE_DLG_H
