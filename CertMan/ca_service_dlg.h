#ifndef CA_SERVICE_DLG_H
#define CA_SERVICE_DLG_H

#include <QDialog>
#include "ui_ca_service_dlg.h"
#include "ca_server.h"

namespace Ui {
class CAServiceDlg;
}

class CAServiceDlg : public QDialog, public Ui::CAServiceDlg
{
    Q_OBJECT

public:
    explicit CAServiceDlg(QWidget *parent = nullptr);
    ~CAServiceDlg();

private slots:
    void clickStart();
    void clickLogClear();
    void clickSelect();
    void clickView();
    void changeNum();

    void clickProfileSelect();
    void clickProfileView();
    void changeProfileNum();

    void checkTLS();
    void clickTLSSelect();
    void clickTLSView();
    void changeTLSNum();

private:
    void initUI();
    void initialize();

    CAServer *ca_srv_;
};

#endif // CA_SERVICE_DLG_H
