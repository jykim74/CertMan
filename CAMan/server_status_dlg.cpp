#include "server_status_dlg.h"
#include "server_status_service.h"


ServerStatusDlg::ServerStatusDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    refreshStatus();

//    connect( ServerStatusService::instance(), SIGNAL(serverStatusChanged()), this, SLOT(refreshStatus()));
}

ServerStatusDlg::~ServerStatusDlg()
{

}

void ServerStatusDlg::refreshStatus()
{
    mServerList->clear();

    foreach (const ServerStatus& status, ServerStatusService::instance()->statuses())
    {
        QListWidgetItem *item = new QListWidgetItem( mServerList );
        item->setData(Qt::DisplayRole, status.url.toString());

        if( status.connected )
        {
            item->setData(Qt::DecorationRole, QIcon(":/images/done.png"));
            item->setData(Qt::ToolTipRole, tr("connected"));
        }
        else
        {
            item->setData(Qt::DecorationRole, QIcon(":/images/red_cross.png"));
            item->setData(Qt::ToolTipRole, tr("disconnected"));
        }

        mServerList->addItem(item);
    }
}
