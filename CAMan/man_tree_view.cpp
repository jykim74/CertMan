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

//    setRootIsDecorated(false);
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
    else if( item->getType() == CM_ITEM_TYPE_CERT_PROFILE )
    {
        menu.addAction(tr("Make Cert Profile"), manApplet->mainWindow(), &MainWindow::makeCertProfile );
    }
    else if( item->getType() == CM_ITEM_TYPE_CRL_PROFILE )
    {
        menu.addAction(tr("Make CRL Profile"), manApplet->mainWindow(), &MainWindow::makeCRLProfile );
    }
    else if( item->getType() == CM_ITEM_TYPE_IMPORT_CERT )
    {
        menu.addAction(tr("Import Certificate"), manApplet->mainWindow(), &MainWindow::importCert );
    }
    else if( item->getType() == CM_ITEM_TYPE_IMPORT_CRL )
    {
        menu.addAction(tr("Import CRL"), manApplet->mainWindow(), &MainWindow::importCRL );
    }
    else if( item->getType() == CM_ITEM_TYPE_SUBCA || item->getType() == CM_ITEM_TYPE_ROOTCA )
    {
        if( item->hasChildren() == false )
            menu.addAction(tr("Expand Menu"), manApplet->mainWindow(), &MainWindow::expandMenu );
    }
    else if( item->getType() == CM_ITEM_TYPE_CA )
    {
        menu.addAction(tr("Make Certificate"), manApplet->mainWindow(), &MainWindow::makeCertificate );
        menu.addAction(tr("Make CRL"), manApplet->mainWindow(), &MainWindow::makeCRL );
    }
    else if( item->getType() == CM_ITEM_TYPE_CERT )
    {

    }
    else if( item->getType() == CM_ITEM_TYPE_ADMIN )
    {
        menu.addAction(tr("Register Admin"), manApplet->mainWindow(), &MainWindow::registerAdmin );
    }
    else if( item->getType() == CM_ITEM_TYPE_USER )
    {
        menu.addAction(tr("Register User"), manApplet->mainWindow(), &MainWindow::registerUser );
    }
    else if( item->getType() == CM_ITEM_TYPE_REG_SIGNER )
    {
        menu.addAction(tr("Regiter Signer"), manApplet->mainWindow(), &MainWindow::registerREGSigner);
    }
    else if( item->getType() == CM_ITEM_TYPE_OCSP_SIGNER )
    {
        menu.addAction(tr("Register Signer"), manApplet->mainWindow(), &MainWindow::registerOCSPSigner);
    }
    else if( item->getType() == CM_ITEM_TYPE_KMS )
    {
        menu.addAction(tr("Register Key"), manApplet->mainWindow(), &MainWindow::registerKey );
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
