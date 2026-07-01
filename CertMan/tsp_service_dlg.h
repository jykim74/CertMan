#ifndef TSP_SERVER_DLG_H
#define TSP_SERVER_DLG_H

#include <QDialog>


#include "ui_tsp_service_dlg.h"
#include "tsp_server.h"


namespace Ui {
class TSPServiceDlg;
}

class TSPServiceDlg : public QDialog, public Ui::TSPServiceDlg
{
    Q_OBJECT

public:
    explicit TSPServiceDlg(QWidget *parent = nullptr);
    ~TSPServiceDlg();

private slots:
    void checkTLS();

    void clickStart();
    void clickStop();
    void clickLogClear();
    void clickSelect();
    void clickView();
    void changeNum();

    void clickTLSSelect();
    void clickTLSView();
    void changeTLSNum();

private:
    void initUI();
    void initialize();

    TSPServer *tsp_srv_;
};

#endif // TSP_SERVER_DLG_H
