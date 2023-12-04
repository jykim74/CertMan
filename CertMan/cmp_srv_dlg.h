#ifndef CMP_SRV_DLG_H
#define CMP_SRV_DLG_H

#include <QDialog>
#include "ui_cmp_srv_dlg.h"

namespace Ui {
class CMPSrvDlg;
}

class CMPSrvDlg : public QDialog, public Ui::CMPSrvDlg
{
    Q_OBJECT

public:
    explicit CMPSrvDlg(QWidget *parent = nullptr);
    ~CMPSrvDlg();

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

#endif // CMP_SRV_DLG_H
