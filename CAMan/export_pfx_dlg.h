#ifndef EXPORT_PFX_DLG_H
#define EXPORT_PFX_DLG_H

#include <QDialog>

namespace Ui {
class ExportPFXDlg;
}

class ExportPFXDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportPFXDlg(QWidget *parent = nullptr);
    ~ExportPFXDlg();

private:
    Ui::ExportPFXDlg *ui;
};

#endif // EXPORT_PFX_DLG_H
