#ifndef CA_MAN_DLG_H
#define CA_MAN_DLG_H

#include <QDialog>
#include "ui_ca_man_dlg.h"

enum {
    CAManModeManage = 0,
    CAManModeSelectCACert,
    CAManModeSelectKeyPair,
    CAManModeSelectCSR
};

enum {
    TAB_CA_CERT_IDX = 0,
    TAB_KEYPAIR_IDX = 1,
    TAB_CSR_IDX = 2
};

namespace Ui {
class CAManDlg;
}

class CAManDlg : public QDialog, public Ui::CAManDlg
{
    Q_OBJECT

public:
    explicit CAManDlg(QWidget *parent = nullptr);
    ~CAManDlg();

    void setMode( int nMode );
    void setTitle( const QString strTitle );
    int getNum() { return num_; };

private slots:
    void showEvent(QShowEvent *event);
    void changeTab( int index );

    void clickOK();

    void loadCACertList();
    void loadKeyPairList();
    void loadCSRList();

    void clickCACertView();
    void clickCACertDelete();
    void clickKeyPairView();
    void clickKeyPairDelete();
    void clickCSRView();
    void clickCSRDelete();

private:
    void initUI();
    void initialize();

    int num_;
};

#endif // CA_MAN_DLG_H
