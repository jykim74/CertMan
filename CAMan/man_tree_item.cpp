#include "man_tree_item.h"

ManTreeItem::ManTreeItem()
{
    type_ = -1;
    data_num_ = -1;
}

ManTreeItem::ManTreeItem(const QString name )
{
    this->setText(name);
}

void ManTreeItem::setType(int type)
{
    type_ = type;
}

void  ManTreeItem::setDataNum( int data_num )
{
    data_num_ = data_num;
}
