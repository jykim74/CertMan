#include "remote_db_dlg.h"
#include "commons.h"
#include "man_applet.h"

RemoteDBDlg::RemoteDBDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mConnectBtn, SIGNAL(clicked()), this, SLOT(clickConnect()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initialize();
}

RemoteDBDlg::~RemoteDBDlg()
{

}

void RemoteDBDlg::initialize()
{
    mDBTypeCombo->addItems( kRemoteDBList );
}

void RemoteDBDlg::clickClear()
{
    mHostnameText->clear();
    mUsernameText->clear();
    mPasswordText->clear();
    mDBNameText->clear();
}

void RemoteDBDlg::clickConnect()
{

}
