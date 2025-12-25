#include "progress_dlg.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "commons.h"

ProgressDlg::ProgressDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
}

ProgressDlg::~ProgressDlg()
{

}

void ProgressDlg::setCmd( int nCmd )
{
    cmd_ = nCmd;

    switch (cmd_) {
    case kCmdEncPriKey:
    case kCmdChangeEnc:
        int nKeyCount = manApplet->dbMgr()->getKeyPairCountAll();
        setMaxValue( nKeyCount );
        break;

    default:
        break;
    }
}

void ProgressDlg::setMaxValue( int nMax )
{
    mProgBar->setMaximum( nMax );
    mTotalText->setText( QString( "%1" ).arg( nMax ));
}

void ProgressDlg::clickStart()
{
    int ret = 0;
    switch (cmd_) {
    case kCmdEncPriKey:
        ret = runEncryptPrivateKey();
        break;

    case kCmdChangeEnc:
        ret = runChangeEncrypt();
        break;

    default:
        break;
    }
}

int ProgressDlg::runEncryptPrivateKey()
{
    return 0;
}


int ProgressDlg::runChangeEncrypt()
{
    return 0;
}
