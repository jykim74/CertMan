#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "crl_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"

CRLInfoDlg::CRLInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
}

CRLInfoDlg::~CRLInfoDlg()
{

}

void CRLInfoDlg::setCRLNum(int crl_num)
{
    crl_num_ = crl_num;
}
