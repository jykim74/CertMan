/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include <QStandardItemModel>
#include "man_tree_item.h"
#include "man_tree_view.h"
#include "cert_rec.h"

class ManTreeModel : public QStandardItemModel
{
    Q_OBJECT

public:
    ManTreeModel( QObject *parent = 0 );
    ~ManTreeModel();

    void clickTreeMenu( int nType, int nNum = -1 );
    void clickRootTreeMenu( int nType, int nNum = -1 );
    void createTreeMenu();
    void expandItem( ManTreeItem *item );
    void refreshRootCA();
    void addRootCA( CertRec& certRec );

    ManTreeView* getTreeView() { return tree_view_; };
    ManTreeItem* currentItem();

private:
    ManTreeView     *tree_view_;
    ManTreeItem     *root_ca_;
};

#endif // MAN_TREE_MODEL_H
