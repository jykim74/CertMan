#ifndef REVOKE_CERT_DLG_H
#define REVOKE_CERT_DLG_H

#include <QDialog>

namespace Ui {
class RevokeCertDlg;
}

class RevokeCertDlg : public QDialog
{
    Q_OBJECT

public:
    explicit RevokeCertDlg(QWidget *parent = nullptr);
    ~RevokeCertDlg();

private:
    Ui::RevokeCertDlg *ui;
};

#endif // REVOKE_CERT_DLG_H
