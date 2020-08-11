#include "server_status_dlg.h"
#include "server_status_service.h"


ServerStatusDlg::ServerStatusDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    refreshStatus();

    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(refresh()));
//    connect( ServerStatusService::instance(), SIGNAL(serverStatusChanged()), this, SLOT(refreshStatus()));
}

ServerStatusDlg::~ServerStatusDlg()
{

}

void ServerStatusDlg::refreshStatus()
{
    mServerList->clear();
    QHash<QString, ServerStatus> statuses = ServerStatusService::instance()->statuses();
    QList<QString> keys = statuses.keys();

    for( int i = 0; i < keys.size(); i++ )
    {
        QString strName = keys.at(i);
        ServerStatus status = statuses[strName];

        QListWidgetItem *item = new QListWidgetItem( mServerList );

        QString strLabel = strName;
        strLabel += " [ ";
        strLabel += status.url.toString();
        strLabel += " ] ";

        item->setData( Qt::DisplayRole, strLabel );

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

void ServerStatusDlg::refresh()
{
    ServerStatusService::instance()->refresh();
    refreshStatus();
}
