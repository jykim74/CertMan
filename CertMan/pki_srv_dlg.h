#ifndef PKI_SRV_DLG_H
#define PKI_SRV_DLG_H

#include <QDialog>
#include "ui_pki_srv_dlg.h"

namespace Ui {
class PKISrvDlg;
}

class PKISrvDlg : public QDialog, public Ui::PKISrvDlg
{
    Q_OBJECT

public:
    explicit PKISrvDlg(QWidget *parent = nullptr);
    ~PKISrvDlg();
    void setSrvKind( int nKind );

private slots:
    void showEvent(QShowEvent *event);

    void clickDel();
    void clickAdd();
    void clickFindFile();
    void clickFindServer();
    void clickCheck();
    void clickStart();

    void slotConfigMenuRequested(QPoint pos);
    void deleteConfigMenu();

    void clickConnect();
    void clickListPid();
    void clickGetProc();
    void clickGetService();
    void clickListThread();
    void clickGetThread();
    void clickResize();
    void clickStop();

private:
    void initialize();
    void clearTable();
    void loadTable();

    const QString getName();

    int kind_;
};

#endif // PKI_SRV_DLG_H
