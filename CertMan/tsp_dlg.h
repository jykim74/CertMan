#ifndef TSP_DLG_H
#define TSP_DLG_H

#include <QDialog>
#include "ui_tsp_dlg.h"

namespace Ui {
class TSPDlg;
}

class TSPDlg : public QDialog, public Ui::TSPDlg
{
    Q_OBJECT

public:
    explicit TSPDlg(QWidget *parent = nullptr);
    ~TSPDlg();

private slots:
    void clickSend();
    void clickClose();
    void clickViewTSTInfo();
    void clickVerifyTSP();

private:

};

#endif // TSP_DLG_H
