#ifndef TSP_SERVER_DLG_H
#define TSP_SERVER_DLG_H

#include <QDialog>


#include "ui_tsp_server_dlg.h"
#include "tsp_server.h"


namespace Ui {
class TSPServerDlg;
}

class TSPServerDlg : public QDialog, public Ui::TSPServerDlg
{
    Q_OBJECT

public:
    explicit TSPServerDlg(QWidget *parent = nullptr);
    ~TSPServerDlg();

private slots:
    void clickStart();
    void clickLogClear();

private:
    void initUI();
    void initialize();

    TSPServer *tsp_srv_;
};

#endif // TSP_SERVER_DLG_H
