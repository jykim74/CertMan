#ifndef MAKE_CERT_DLG_H
#define MAKE_CERT_DLG_H

#include <QDialog>
#include "ui_make_cert_dlg.h"

namespace Ui {
class MakeCertDlg;
}

class MakeCertDlg : public QDialog, public Ui::MakeCertDlg
{
    Q_OBJECT

public:
    explicit MakeCertDlg(QWidget *parent = nullptr);
    ~MakeCertDlg();

private:

};

#endif // MAKE_CERT_DLG_H
