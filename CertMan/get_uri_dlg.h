/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef GET_URI_DLG_H
#define GET_URI_DLG_H

#include <QDialog>
#include "ui_get_uri_dlg.h"
#include "js_bin.h"

namespace Ui {
class GetURIDlg;
}

class GetURIDlg : public QDialog, public Ui::GetURIDlg
{
    Q_OBJECT

public:
    explicit GetURIDlg(QWidget *parent = nullptr);
    ~GetURIDlg();

private slots:
    void showEvent(QShowEvent *event);
    void clickUseLDAPHost();
    void clickClearUsedURI();
    void clickGet();
    void changeURI( int index );

private:
    void initUI();
    void initialize();

    int ImportCRL( const BIN *pCRL, const QString strURI );
    int ImportCert( const BIN *pCert );

    QStringList getUsedURI();
    void saveUsedURI( const QString &strURL );

    const QString getValidURL();
    int getLDAP( BIN *pData );
    int getHTTP( BIN *pData );
};

#endif // GET_LDAP_DLG_H
