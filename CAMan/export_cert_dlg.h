#ifndef EXPORT_CERT_DLG_H
#define EXPORT_CERT_DLG_H

#include <QDialog>

namespace Ui {
class ExportCertDlg;
}

class ExportCertDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportCertDlg(QWidget *parent = nullptr);
    ~ExportCertDlg();

private:
    Ui::ExportCertDlg *ui;
};

#endif // EXPORT_CERT_DLG_H
