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

private:
;
};

#endif // PUB_LDAP_DLG_H
