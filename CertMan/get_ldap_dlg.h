#ifndef GET_LDAP_DLG_H
#define GET_LDAP_DLG_H

#include <QDialog>
#include "ui_get_ldap_dlg.h"
#include "js_bin.h"

namespace Ui {
class GetLDAPDlg;
}

class GetLDAPDlg : public QDialog, public Ui::GetLDAPDlg
{
    Q_OBJECT

public:
    explicit GetLDAPDlg(QWidget *parent = nullptr);
    ~GetLDAPDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();
    void clickUseURI();


private:
    void initUI();
    void initialize();

    int ImportCRL( const BIN *pCRL );
    int ImportCert( const BIN *pCert );

    QStringList getUsedURI();
    void saveUsedURI( const QString &strURL );
};

#endif // GET_LDAP_DLG_H
