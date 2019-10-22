#ifndef EXPORT_REQ_DLG_H
#define EXPORT_REQ_DLG_H

#include <QDialog>

namespace Ui {
class ExportReqDlg;
}

class ExportReqDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ExportReqDlg(QWidget *parent = nullptr);
    ~ExportReqDlg();

private:
    Ui::ExportReqDlg *ui;
};

#endif // EXPORT_REQ_DLG_H
