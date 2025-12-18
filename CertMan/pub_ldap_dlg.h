/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef PUB_LDAP_DLG_H
#define PUB_LDAP_DLG_H

#include <QDialog>
#include "ui_pub_ldap_dlg.h"

namespace Ui {
class PubLDAPDlg;
}

class PubLDAPDlg : public QDialog, public Ui::PubLDAPDlg
{
    Q_OBJECT

public:
    explicit PubLDAPDlg(QWidget *parent = nullptr);
    ~PubLDAPDlg();

    int dataType() { return data_type_; };
    int dataNum() { return data_num_; };

    void setDataType( int data_type );
    void setDataNum( int data_num );

    void setPublishDN( const QString strDN );

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void dataTypeChanged(int index);

    QString getDefault();
    void setDefault( const QString& strDefault );


private:
    void initUI();
    void initialize();

    int data_type_;
    int data_num_;
};

#endif // PUB_LDAP_DLG_H
