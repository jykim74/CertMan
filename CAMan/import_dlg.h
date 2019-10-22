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

private:
};

#endif // IMPORT_DLG_H
