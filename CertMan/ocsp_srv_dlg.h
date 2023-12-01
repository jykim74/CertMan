#ifndef OCSP_SRV_DLG_H
#define OCSP_SRV_DLG_H

#include <QDialog>
#include "ui_ocsp_srv_dlg.h"

namespace Ui {
class OCSPSrvDlg;
}

class OCSPSrvDlg : public QDialog, public Ui::OCSPSrvDlg
{
    Q_OBJECT

public:
    explicit OCSPSrvDlg(QWidget *parent = nullptr);
    ~OCSPSrvDlg();

private:

};

#endif // OCSP_SRV_DLG_H
