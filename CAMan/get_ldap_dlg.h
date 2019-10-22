#ifndef GET_LDAP_DLG_H
#define GET_LDAP_DLG_H

#include <QDialog>

namespace Ui {
class GetLDAPDlg;
}

class GetLDAPDlg : public QDialog
{
    Q_OBJECT

public:
    explicit GetLDAPDlg(QWidget *parent = nullptr);
    ~GetLDAPDlg();

private:
    Ui::GetLDAPDlg *ui;
};

#endif // GET_LDAP_DLG_H
