#ifndef MAN_TREE_ITEM_H
#define MAN_TREE_ITEM_H

#include <QStandardItem>

#define CM_ITEM_TYPE_KEYPAIR        1
#define CM_ITEM_TYPE_REQUEST        2
#define CM_ITEM_TYPE_CERT_POLICY    3
#define CM_ITEM_TYPE_CRL_POLICY     4
#define CM_ITEM_TYPE_ROOTCA         5
#define CM_ITEM_TYPE_IMPORT_CERT    6
#define CM_ITEM_TYPE_IMPORT_CRL     7
#define CM_ITEM_TYPE_CERT           8
#define CM_ITEM_TYPE_CRL            9
#define CM_ITEM_TYPE_REVOKE         10
#define CM_ITEM_TYPE_CA             11

class ManTreeItem : public QStandardItem
{
public:
    ManTreeItem();
    ManTreeItem( const QString name );
    int getType() { return type_; };
    void setType( int type );

private:
    int     type_;
};

#endif // MAN_TREE_ITEM_H
