#ifndef CA_SERVICE_DLG_H
#define CA_SERVICE_DLG_H

#include <QDialog>
#include "ui_ca_service_dlg.h"

namespace Ui {
class CAServiceDlg;
}

class CAServiceDlg : public QDialog, public Ui::CAServiceDlg
{
    Q_OBJECT

public:
    explicit CAServiceDlg(QWidget *parent = nullptr);
    ~CAServiceDlg();

private:

};

#endif // CA_SERVICE_DLG_H
