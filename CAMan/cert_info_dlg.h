#ifndef CERT_INFO_DLG_H
#define CERT_INFO_DLG_H

#include <QDialog>
#include "ui_cert_info_dlg.h"

namespace Ui {
class CertInfoDlg;
}

class CertInfoDlg : public QDialog, public Ui::CertInfoDlg
{
    Q_OBJECT

public:
    explicit CertInfoDlg(QWidget *parent = nullptr);
    ~CertInfoDlg();

private:
};

#endif // CERT_INFO_DLG_H
