#ifndef GET_LDAP_DLG_H
#define GET_LDAP_DLG_H

#include <QDialog>
#include "ui_get_ldap_dlg.h"

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


private:
    void initUI();
    void initialize();

private:

};

#endif // GET_LDAP_DLG_H
