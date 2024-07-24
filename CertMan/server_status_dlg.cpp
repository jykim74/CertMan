/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "server_status_dlg.h"
#include "server_status_service.h"


ServerStatusDlg::ServerStatusDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    refreshStatus();

    connect( mRefreshBtn, SIGNAL(clicked()), this, SLOT(refresh()));
//    connect( ServerStatusService::instance(), SIGNAL(serverStatusChanged()), this, SLOT(refreshStatus()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ServerStatusDlg::~ServerStatusDlg()
{

}

void ServerStatusDlg::refreshStatus()
{
    mServerList->clear();
    QHash<QString, ServerStatus> statuses = ServerStatusService::instance()->statuses();
    QList<QString> keys = statuses.keys();

    if( keys.size() == 0 )
    {
        QString strLabel = tr("There is no list or ServerStatus is not set in settings" );
        QListWidgetItem *item = new QListWidgetItem( mServerList );
        item->setData( Qt::DisplayRole, strLabel );
        return;
    }

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
