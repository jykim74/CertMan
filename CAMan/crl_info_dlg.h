#ifndef CRL_INFO_DLG_H
#define CRL_INFO_DLG_H

#include <QDialog>
#include "ui_crl_info_dlg.h"

namespace Ui {
class CRLInfoDlg;
}

class CRLInfoDlg : public QDialog, public Ui::CRLInfoDlg
{
    Q_OBJECT

public:
    explicit CRLInfoDlg(QWidget *parent = nullptr);
    ~CRLInfoDlg();

private:

};

#endif // CRL_INFO_DLG_H
