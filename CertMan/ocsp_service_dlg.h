#ifndef OCSP_SERVICE_DLG_H
#define OCSP_SERVICE_DLG_H

#include <QDialog>
#include "ui_ocsp_service_dlg.h"

namespace Ui {
class OCSPServiceDlg;
}

class OCSPServiceDlg : public QDialog, public Ui::OCSPServiceDlg
{
    Q_OBJECT

public:
    explicit OCSPServiceDlg(QWidget *parent = nullptr);
    ~OCSPServiceDlg();

private:

};

#endif // OCSP_SERVICE_DLG_H
