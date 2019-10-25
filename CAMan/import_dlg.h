#ifndef IMPORT_DLG_H
#define IMPORT_DLG_H

#include <QDialog>
#include "ui_import_dlg.h"

namespace Ui {
class ImportDlg;
}

class ImportDlg : public QDialog, public Ui::ImportDlg
{
    Q_OBJECT

public:
    explicit ImportDlg(QWidget *parent = nullptr);
    ~ImportDlg();

private slots:
    void showEvent(QShowEvent *event);
    virtual void accept();

    void clickFind();
    void dataTypeChanged( int index );

private:
    void initUI();
    void initialize();

private:
};

#endif // IMPORT_DLG_H
