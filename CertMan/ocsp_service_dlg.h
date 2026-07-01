#ifndef OCSP_SERVICE_DLG_H
#define OCSP_SERVICE_DLG_H

#include <QDialog>
#include "ui_ocsp_service_dlg.h"
#include "ocsp_server.h"

namespace Ui {
class OCSPServiceDlg;
}

class OCSPServiceDlg : public QDialog, public Ui::OCSPServiceDlg
{
    Q_OBJECT

public:
    explicit OCSPServiceDlg(QWidget *parent = nullptr);
    ~OCSPServiceDlg();

private slots:
    void clickStart();
    void clickStop();
    void clickLogClear();
    void clickCASelect();
    void clickCAView();
    void changeCANum();
    void clickSelect();
    void clickView();
    void changeNum();

    void checkTLS();
    void clickTLSSelect();
    void clickTLSView();
    void changeTLSNum();

private:
    void initUI();
    void initialize();

    OCSPServer *ocsp_srv_;
};

#endif // OCSP_SERVICE_DLG_H
