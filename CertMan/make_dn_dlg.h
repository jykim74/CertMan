#ifndef MAKE_DN_DLG_H
#define MAKE_DN_DLG_H

#include <QDialog>
#include "ui_make_dn_dlg.h"

namespace Ui {
class MakeDNDlg;
}

class MakeDNDlg : public QDialog, public Ui::MakeDNDlg
{
    Q_OBJECT

public:
    explicit MakeDNDlg(QWidget *parent = nullptr);
    ~MakeDNDlg();
    void setDN( const QString strDN );
    const QString getDN();

private:

};

#endif // MAKE_DN_DLG_H
