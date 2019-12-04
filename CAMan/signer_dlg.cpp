#include <QFileDialog>

#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "signer_dlg.h"

#include "js_bin.h"
#include "js_pki_x509.h"

static QStringList sTypeList = { "REG Signer", "OCSP Signer" };

SignerDlg::SignerDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
}

SignerDlg::~SignerDlg()
{

}

void SignerDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void SignerDlg::findCert()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Import files"),
                                                     QDir::currentPath(),
                                                     tr("Cert Files (*.crt);;Key Files (*.key);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mCertPathText->setText(fileName);
}

void SignerDlg::accept()
{

}

void SignerDlg::initialize()
{

}

void SignerDlg::initUI()
{
    mTypeCombo->addItems(sTypeList);
    connect( mFindCertBtn, SIGNAL(clicked()), this, SLOT(findCert()));
}
