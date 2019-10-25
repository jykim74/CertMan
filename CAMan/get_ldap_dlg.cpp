#include "get_ldap_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"


static QStringList sDataAttributeList = {
    "caCertificate", "signCertificate", "userCertificate", "certificateRevocationList", "authorityRevocationList"
};

static QStringList sFilterList = {
    "BASE"
};

GetLDAPDlg::GetLDAPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

GetLDAPDlg::~GetLDAPDlg()
{

}


void GetLDAPDlg::showEvent(QShowEvent *event)
{

}

void GetLDAPDlg::accept()
{

}

void GetLDAPDlg::initUI()
{
    mSearchCombo->addItems(sDataAttributeList);
    mFilterCombo->addItems(sFilterList);
}

void GetLDAPDlg::initialize()
{

}
