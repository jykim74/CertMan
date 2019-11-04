#include <QMenu>

#include "man_tree_view.h"
#include "man_tree_item.h"
#include "man_tree_model.h"
#include "mainwindow.h"
#include "man_applet.h"

ManTreeView::ManTreeView( QWidget *parent )
    : QTreeView (parent)
{
    setAcceptDrops(false);
    setContextMenuPolicy(Qt::CustomContextMenu);

    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showContextMenu(QPoint)));
}

void ManTreeView::showContextMenu(QPoint point)
{
    ManTreeItem* item = currentItem();

    if( item == NULL ) return;

    QMenu menu(this);

    if( item->getType() == CM_ITEM_TYPE_KEYPAIR )
    {
        menu.addAction(tr("New Key"), manApplet->mainWindow(), &MainWindow::newKey);
    }
    else if( item->getType() == CM_ITEM_TYPE_REQUEST )
    {
        menu.addAction(tr("Make Request"), manApplet->mainWindow(), &MainWindow::makeRequest );
        menu.addAction(tr("Make Certificate"), manApplet->mainWindow(), &MainWindow::makeCertificate );
    }
    else if( item->getType() == CM_ITEM_TYPE_CERT_POLICY )
    {
        menu.addAction(tr("Make Cert Policy"), manApplet->mainWindow(), &MainWindow::makeCertPolicy );
    }
    else if( item->getType() == CM_ITEM_TYPE_CRL_POLICY )
    {
        menu.addAction(tr("Make CRL Policy"), manApplet->mainWindow(), &MainWindow::makeCRLPolicy );
    }
    else if( item->getType() == CM_ITEM_TYPE_IMPORT_CERT )
    {
        menu.addAction(tr("Import Certificate"), manApplet->mainWindow(), &MainWindow::importData );
    }
    else if( item->getType() == CM_ITEM_TYPE_IMPORT_CRL )
    {
        menu.addAction(tr("Import CRL"), manApplet->mainWindow(), &MainWindow::importData );
    }

    menu.exec(QCursor::pos());
}


ManTreeItem* ManTreeView::currentItem()
{
    QModelIndex index = currentIndex();

    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *item = (ManTreeItem *)tree_model->itemFromIndex(index);

    return item;
}
