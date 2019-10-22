#ifndef PUB_LDAP_DLG_H
#define PUB_LDAP_DLG_H

#include <QDialog>

namespace Ui {
class PubLDAPDlg;
}

class PubLDAPDlg : public QDialog
{
    Q_OBJECT

public:
    explicit PubLDAPDlg(QWidget *parent = nullptr);
    ~PubLDAPDlg();

private:
    Ui::PubLDAPDlg *ui;
};

#endif // PUB_LDAP_DLG_H
