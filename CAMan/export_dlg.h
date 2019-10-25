#ifndef EXPORT_DLG_H
#define EXPORT_DLG_H

#include <QDialog>
#include "ui_export_dlg.h"

namespace Ui {
class ExportDlg;
}

class ExportDlg : public QDialog, public Ui::ExportDlg
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void clickFind();

private:
    void initUI();
    void initialize();

private:

};

#endif // EXPORT_DLG_H
