#ifndef VIEW_CERT_PROFIL_EDLG_H
#define VIEW_CERT_PROFIL_EDLG_H

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

private:

};

#endif // VIEW_CERT_PROFIL_EDLG_H
