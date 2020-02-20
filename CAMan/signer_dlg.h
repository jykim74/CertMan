#ifndef SIGNER_DLG_H
#define SIGNER_DLG_H

#include <QDialog>
#include "ui_signer_dlg.h"

namespace Ui {
class SignerDlg;
}

class SignerDlg : public QDialog, public Ui::SignerDlg
{
    Q_OBJECT

public:
    explicit SignerDlg(QWidget *parent = nullptr);
    ~SignerDlg();

private slots:
    void findCert();
    virtual void accept();

private:
    void initialize();
    void initUI();

};

#endif // SIGNER_DLG_H
