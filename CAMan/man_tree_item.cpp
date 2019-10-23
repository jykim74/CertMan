#include "man_tree_item.h"

ManTreeItem::ManTreeItem()
{

}

ManTreeItem::ManTreeItem(const QString name )
{
    this->setText(name);
}

void ManTreeItem::setType(int type)
{
    type_ = type;
}
