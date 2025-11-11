/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_TREE_VIEW_H
#define MAN_TREE_VIEW_H

#include <QTreeView>
#include "man_tree_item.h"

class ManTreeItem;

class ManTreeView : public QTreeView
{
    Q_OBJECT
public:
    ManTreeView( QWidget* parent = 0 );
    ManTreeItem* getItem( const ManTreeItem* parent, int nType, int nNum = -1 );

private slots:
    void showContextMenu( QPoint point );

public:
    ManTreeItem* currentItem();
};

#endif // MAN_TREE_VIEW_H
