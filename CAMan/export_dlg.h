#ifndef EXPORT_DLG_H
#define EXPORT_DLG_H

#include <QDialog>

namespace Ui {
class ExportDlg;
}

class ExportDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();

private:
    Ui::ExportDlg *ui;
};

#endif // EXPORT_DLG_H
