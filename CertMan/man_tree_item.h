#ifndef MAN_TREE_ITEM_H
#define MAN_TREE_ITEM_H

#include <QStandardItem>

#define CM_ITEM_TYPE_KEYPAIR        1
#define CM_ITEM_TYPE_REQUEST        2
#define CM_ITEM_TYPE_CERT_PROFILE   3
#define CM_ITEM_TYPE_CRL_PROFILE    4
#define CM_ITEM_TYPE_ROOTCA         5
#define CM_ITEM_TYPE_IMPORT_CERT    6
#define CM_ITEM_TYPE_IMPORT_CRL     7
#define CM_ITEM_TYPE_CERT           8
#define CM_ITEM_TYPE_CRL            9
#define CM_ITEM_TYPE_REVOKE         10
#define CM_ITEM_TYPE_CA             11
#define CM_ITEM_TYPE_SUBCA          12
#define CM_ITEM_TYPE_USER           13
#define CM_ITEM_TYPE_ADMIN          14
#define CM_ITEM_TYPE_CONFIG         15
#define CM_ITEM_TYPE_REG_SIGNER     16
#define CM_ITEM_TYPE_OCSP_SIGNER    17
#define CM_ITEM_TYPE_KMS            18
#define CM_ITEM_TYPE_STATISTICS     19
#define CM_ITEM_TYPE_AUDIT          20
#define CM_ITEM_TYPE_TSP            21




class ManTreeItem : public QStandardItem
{
public:
    ManTreeItem();
    ManTreeItem( const QString name );
    int getType() { return type_; };
    void setType( int type );

    int getDataNum() { return data_num_; };
    void setDataNum( int data_num );

private:
    int     type_;
    int     data_num_;
};

#endif // MAN_TREE_ITEM_H
