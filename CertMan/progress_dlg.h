#ifndef PROGRESS_DLG_H
#define PROGRESS_DLG_H

#include <QDialog>
#include "ui_progress_dlg.h"

const int kCmdEncPriKey = 1;
const int kCmdChangeEnc = 2;

namespace Ui {
class ProgressDlg;
}

class ProgressDlg : public QDialog, public Ui::ProgressDlg
{
    Q_OBJECT

public:
    explicit ProgressDlg(QWidget *parent = nullptr);
    ~ProgressDlg();

    void setCmd( int nCmd );

private slots:
    void clickStart();

private:
    void setMaxValue( int nMax );
    int runEncryptPrivateKey();
    int runChangeEncrypt();

    int cmd_;
};

#endif // PROGRESS_DLG_H
