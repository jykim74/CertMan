#ifndef MAKE_CRL_DLG_H
#define MAKE_CRL_DLG_H

#include <QDialog>
#include "ui_make_crl_dlg.h"

namespace Ui {
class MakeCRLDlg;
}

class MakeCRLDlg : public QDialog, public Ui::MakeCRLDlg
{
    Q_OBJECT

public:
    explicit MakeCRLDlg(QWidget *parent = nullptr);
    ~MakeCRLDlg();

private:
;
};

#endif // MAKE_CRL_DLG_H
