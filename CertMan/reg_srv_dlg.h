#ifndef REG_SRV_DLG_H
#define REG_SRV_DLG_H

#include <QDialog>
#include "ui_reg_srv_dlg.h"

namespace Ui {
class RegSrvDlg;
}

class RegSrvDlg : public QDialog, public Ui::RegSrvDlg
{
    Q_OBJECT

public:
    explicit RegSrvDlg(QWidget *parent = nullptr);
    ~RegSrvDlg();

private slots:
    void clickDel();
    void clickAdd();
    void clickFindFile();
    void clickFindServer();
    void clickCheck();
    void clickStart();

    void slotConfigMenuRequested(QPoint pos);
    void deleteConfigMenu();

private:
    void initialize();
    void clearTable();
    void loadTable();
};

#endif // REG_SRV_DLG_H
