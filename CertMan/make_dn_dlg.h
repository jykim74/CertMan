#ifndef MAKE_DN_DLG_H
#define MAKE_DN_DLG_H

#include <QDialog>
#include "ui_make_cert_dlg.h"

namespace Ui {
class MakeDNDlg;
}

class MakeDNDlg : public QDialog, public Ui::MakeCertDlg
{
    Q_OBJECT

public:
    explicit MakeDNDlg(QWidget *parent = nullptr);
    ~MakeDNDlg();

private:

};

#endif // MAKE_DN_DLG_H
