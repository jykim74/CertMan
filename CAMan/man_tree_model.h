#ifndef MAN_TREE_MODEL_H
#define MAN_TREE_MODEL_H

#include <QStandardItemModel>


class ManTreeModel : public QStandardItemModel
{
    Q_OBJECT

public:
    ManTreeModel( QObject *parent = 0 );
};

#endif // MAN_TREE_MODEL_H
