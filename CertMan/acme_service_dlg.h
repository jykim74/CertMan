#ifndef ACME_SERVICE_DLG_H
#define ACME_SERVICE_DLG_H

#include <QDialog>
#include "ui_acme_service_dlg.h"
#include "acme_server.h"

namespace Ui {
class ACMEServiceDlg;
}

class ACMEServiceDlg : public QDialog, public Ui::ACMEServiceDlg
{
    Q_OBJECT

public:
    explicit ACMEServiceDlg(QWidget *parent = nullptr);
    ~ACMEServiceDlg();

private slots:
    void clickStart();
    void clickStop();
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

    QString getDefault();
    void setDefault( const QString strDefault );

    ACMEServer *acme_srv_;

};

#endif // ACME_SERVICE_DLG_H
