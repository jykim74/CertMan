#ifndef EXPORT_PRI_KEY_DLG_H
#define EXPORT_PRI_KEY_DLG_H

#include <QDialog>

namespace Ui {
class ExportPriKeyDlg;
}

class ExportPriKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportPriKeyDlg(QWidget *parent = nullptr);
    ~ExportPriKeyDlg();

private:
    Ui::ExportPriKeyDlg *ui;
};

#endif // EXPORT_PRI_KEY_DLG_H
