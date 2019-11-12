#ifndef CHECK_CERT_DLG_H
#define CHECK_CERT_DLG_H

#include <QDialog>
#include "ui_check_cert_dlg.h"

namespace Ui {
class CheckCertDlg;
}

class CheckCertDlg : public QDialog, public Ui::CheckCertDlg
{
    Q_OBJECT

public:
    explicit CheckCertDlg(QWidget *parent = nullptr);
    ~CheckCertDlg();

private:

};

#endif // CHECK_CERT_DLG_H
