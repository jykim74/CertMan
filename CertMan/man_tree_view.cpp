/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QMenu>

#include "man_tree_view.h"
#include "man_tree_item.h"
#include "man_tree_model.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "settings_mgr.h"
#include "commons.h"
#include "cert_info_dlg.h"

ManTreeView::ManTreeView( QWidget *parent )
    : QTreeView (parent)
{
    setAcceptDrops(false);
    setContextMenuPolicy(Qt::CustomContextMenu);

//    setRootIsDecorated(false);
    connect( this, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showContextMenu(QPoint)));

    QFile qss(":/certman.qss");
    qss.open( QFile::ReadOnly );
    setStyleSheet(qss.readAll());
    qss.close();

    static QFont font;
    QString strFont = manApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    setFont(font);
}

ManTreeItem* ManTreeView::getItem( const ManTreeItem* parent, int nType, int nNum )
{
    if( parent == NULL ) return nullptr;

    int row = parent->rowCount();
    QString strName = parent->text();

    for( int i = 0; i < row; i++ )
    {
        ManTreeItem* item = (ManTreeItem *)parent->child(i);

        if( item == nullptr ) continue;

        QString strChildName = item->text();

        if( item->getType() == nType )
        {
            if( nNum >= 0 || nNum == kImportNum )
            {
                if( item->getDataNum() == nNum )
                    return item;
            }
            else
            {
                return item;
            }
        }

        if( item->hasChildren() == true )
        {
            ManTreeItem* child = getItem( item, nType, nNum );
            if( child != nullptr ) return child;
        }
    }

    return nullptr;
}

void ManTreeView::showContextMenu(QPoint point)
{
    ManTreeItem* item = currentItem();

    if( item == NULL ) return;

    QMenu menu(this);

    if( item->getType() == CM_ITEM_TYPE_KEYPAIR )
    {
        menu.addAction(tr("New Key"), manApplet->mainWindow(), &MainWindow::newKey);
        menu.addAction( tr("Import PriKey"), manApplet->mainWindow(), &MainWindow::importPriKey );
        menu.addAction(tr("Import Enc PriKey"), manApplet->mainWindow(), &MainWindow::importEncPriKey );
    }
    else if( item->getType() == CM_ITEM_TYPE_REQUEST )
    {
        menu.addAction(tr("Make Request"), manApplet->mainWindow(), &MainWindow::makeRequest );
        menu.addAction(tr("Make Certificate"), manApplet->mainWindow(), &MainWindow::makeCertificate );
        menu.addAction(tr("Import CSR"), manApplet->mainWindow(), &MainWindow::importCSR);
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
        menu.addAction(tr( "View Certificate" ), this, SLOT(viewCert()) );
    }
    else if( item->getType() == CM_ITEM_TYPE_CERT )
    {
        menu.addAction(tr("Make Certificate"), manApplet->mainWindow(), &MainWindow::makeCertificate );
    }
    else if( item->getType() == CM_ITEM_TYPE_CRL )
    {
        menu.addAction(tr("Make CRL"), manApplet->mainWindow(), &MainWindow::makeCRL );
    }
    else if( item->getType() == CM_ITEM_TYPE_ADMIN )
    {
        menu.addAction(tr("Register Admin"), manApplet->mainWindow(), &MainWindow::registerAdmin );
    }
    else if( item->getType() == CM_ITEM_TYPE_CONFIG )
    {
        menu.addAction(tr("Make Config"), manApplet->mainWindow(), &MainWindow::makeConfig );
        if( manApplet->isPRO() == true && item->getDataNum() > 0 )
            menu.addAction( tr("Server Config" ), manApplet->mainWindow(), &MainWindow::serverConfig );
    }
    else if( item->getType() == CM_ITEM_TYPE_USER )
    {
        menu.addAction(tr("Register User"), manApplet->mainWindow(), &MainWindow::registerUser );
    }
    else if( item->getType() == CM_ITEM_TYPE_REG_SIGNER )
    {
        menu.addAction(tr("Register Signer"), manApplet->mainWindow(), &MainWindow::registerREGSigner);
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

void ManTreeView::viewCert()
{
    ManTreeItem* item = currentItem();
    if( item == NULL ) return;

    int num = item->getDataNum();

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertNum( num );
    certInfoDlg.exec();
}

ManTreeItem* ManTreeView::currentItem()
{
    QModelIndex index = currentIndex();

    ManTreeModel *tree_model = (ManTreeModel *)model();
    ManTreeItem *item = (ManTreeItem *)tree_model->itemFromIndex(index);

    return item;
}
