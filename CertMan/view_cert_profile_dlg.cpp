#include "view_cert_profile_dlg.h"

ViewCertProfileDlg::ViewCertProfileDlg(QWidget *parent)
    : QDialog(parent)
{
    profile_num_ = -1;
    setupUi(this);
}

ViewCertProfileDlg::~ViewCertProfileDlg()
{

}

int ViewCertProfileDlg::setProfile( int nNum )
{
    return 0;
}
