#include "make_crl_policy_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "policy_ext_rec.h"
#include "crl_policy_rec.h"
#include "db_mgr.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
static QStringList sTypeList = { "URI", "email", "DNS" };
static QStringList sVersionList = { "V1", "V2" };


MakeCRLPolicyDlg::MakeCRLPolicyDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

MakeCRLPolicyDlg::~MakeCRLPolicyDlg()
{

}


void MakeCRLPolicyDlg::showEvent(QShowEvent *event)
{

}

void MakeCRLPolicyDlg::accept()
{

}

void MakeCRLPolicyDlg::initUI()
{
    mHashCombo->addItems(sHashList);
    mDPNCombo->addItems(sTypeList);
    mIANCombo->addItems(sTypeList);
    mVersionCombo->addItems(sVersionList);
}
