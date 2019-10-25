#include "pub_ldap_dlg.h"

static QStringList sTypeList = { "Certificate", "CRL" };

static QStringList sCertAttributeList = {
    "caCertificate", "signCertificate", "userCertificate"
};


static QStringList sCRLAttributeList = {
    "certificateRevocationList", "authorityRevocationList"
};

PubLDAPDlg::PubLDAPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

PubLDAPDlg::~PubLDAPDlg()
{

}

void PubLDAPDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void PubLDAPDlg::accept()
{

}

void PubLDAPDlg::initUI()
{
    mTypeCombo->addItems(sTypeList);

    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
}

void PubLDAPDlg::initialize()
{

}

void PubLDAPDlg::dataTypeChanged(int index)
{
    mAttributeCombo->clear();

    if( index == 0 )
        mAttributeCombo->addItems( sCertAttributeList );
    else {
        mAttributeCombo->addItems( sCRLAttributeList );
    }
}
