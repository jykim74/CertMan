#include <QFileDialog>

#include "import_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

static QStringList sDataTypeList = {
    "PrivateKey", "Encrypted PrivateKey", "Request(CSR)", "Certificate", "CRL", "PFX"
};

ImportDlg::ImportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
}

ImportDlg::~ImportDlg()
{

}


void ImportDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void ImportDlg::accept()
{

}

void ImportDlg::initUI()
{
    mDataTypeCombo->addItems(sDataTypeList);

    connect( mFindBtn, SIGNAL(clicked()), this, SLOT( clickFind()));
    connect( mDataTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
}

void ImportDlg::initialize()
{

}


void ImportDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Import files"),
                                                     "/",
                                                     tr("Cert Files (*.crt);;Key Files (*.key);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}

void ImportDlg::dataTypeChanged( int index )
{
    if( index == 1 || index == 5 )
        mPasswordText->setEnabled(true);
    else {
        mPasswordText->setEnabled(false);
    }
}
