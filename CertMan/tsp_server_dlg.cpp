#include "js_gen.h"
#include "js_pki.h"
#include "js_tsp.h"

#include "tsp_server_dlg.h"
#include "tsp_server.h"
#include "work_thread.h"

#include "man_applet.h"


TSPServerDlg::TSPServerDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    tsp_srv_ = nullptr;

    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));
    connect( mLogClearBtn, SIGNAL(clicked()), this, SLOT(clickLogClear()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    initialize();
}

TSPServerDlg::~TSPServerDlg()
{
    if( tsp_srv_ ) delete tsp_srv_;
}

void TSPServerDlg::initUI()
{
    mPortText->setText( QString("%1").arg( JS_TSP_PORT ));
    mSSLPortText->setText( QString( "%1" ).arg( JS_TSP_SSL_PORT ));
}

void TSPServerDlg::initialize()
{

}

void TSPServerDlg::clickStart()
{
    QString strPort = mPortText->text();

    if( strPort.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a port" ), this );
        mPortText->setFocus();

        return;
    }

    if( tsp_srv_ ) delete tsp_srv_;

    tsp_srv_ = new TSPServer;
    int nPort = strPort.toInt();
    tsp_srv_->setLogEdit( mLogText );
    tsp_srv_->startServer( nPort );
}

void TSPServerDlg::clickLogClear()
{
    mLogText->clear();
}
