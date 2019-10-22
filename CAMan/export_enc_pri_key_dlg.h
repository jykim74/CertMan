#ifndef EXPORT_ENC_PRI_KEY_DLG_H
#define EXPORT_ENC_PRI_KEY_DLG_H

#include <QDialog>

namespace Ui {
class ExportEncPriKeyDlg;
}

class ExportEncPriKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportEncPriKeyDlg(QWidget *parent = nullptr);
    ~ExportEncPriKeyDlg();

private:
    Ui::ExportEncPriKeyDlg *ui;
};

#endif // EXPORT_ENC_PRI_KEY_DLG_H
