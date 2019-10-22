#ifndef EXPORT_CRL_DLG_H
#define EXPORT_CRL_DLG_H

#include <QDialog>

namespace Ui {
class ExportCRLDlg;
}

class ExportCRLDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportCRLDlg(QWidget *parent = nullptr);
    ~ExportCRLDlg();

private:
    Ui::ExportCRLDlg *ui;
};

#endif // EXPORT_CRL_DLG_H
