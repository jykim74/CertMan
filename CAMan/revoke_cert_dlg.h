#ifndef REVOKE_CERT_DLG_H
#define REVOKE_CERT_DLG_H

#include <QDialog>
#include "ui_revoke_cert_dlg.h"

namespace Ui {
class RevokeCertDlg;
}

class RevokeCertDlg : public QDialog, public Ui::RevokeCertDlg
{
    Q_OBJECT

public:
    explicit RevokeCertDlg(QWidget *parent = nullptr);
    ~RevokeCertDlg();

private:

};

#endif // REVOKE_CERT_DLG_H
