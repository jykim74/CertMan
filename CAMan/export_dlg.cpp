#include <QFileDialog>

#include "export_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

ExportDlg::ExportDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

ExportDlg::~ExportDlg()
{

}

void ExportDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void ExportDlg::accept()
{

}

void ExportDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("QFileDialog::getOpenFileName()"),
                                                     "/",
                                                     tr("Cert Files (*.crt);;Key Files (*.key);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}

void ExportDlg::initUI()
{
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
}

void ExportDlg::initialize()
{

}
