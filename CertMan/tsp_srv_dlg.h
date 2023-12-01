#ifndef TSP_SRV_DLG_H
#define TSP_SRV_DLG_H

#include <QDialog>
#include "ui_tsp_srv_dlg.h"

namespace Ui {
class TSPSrvDlg;
}

class TSPSrvDlg : public QDialog, public Ui::TSPSrvDlg
{
    Q_OBJECT

public:
    explicit TSPSrvDlg(QWidget *parent = nullptr);
    ~TSPSrvDlg();

private:

};

#endif // TSP_SRV_DLG_H
