#ifndef SETTINGS_DLG_H
#define SETTINGS_DLG_H

#include <QDialog>
#include "ui_settings_dlg.h"

namespace Ui {
class SettingsDlg;
}

class SettingsDlg : public QDialog, public Ui::SettingsDlg
{
    Q_OBJECT

public:
    explicit SettingsDlg(QWidget *parent = nullptr);
    ~SettingsDlg();

private slots:
    void updateSettings();
    virtual void accept();

    void initialize();

    void checkP11Use();
    void findP11Path();
    void checkKMIPUse();

    void findCACert();
    void findCert();
    void findPrivateKey();

    void checkOCSPUse();
    void findOCSPSrvCert();
    void checkOCSPAttachSign();
    void findOCSPPri();
    void findOCSPCert();

    void checkREGUse();
    void checkCMPUse();
    void findCMPRootCACert();
    void findCMPCACert();
    void checkTSPUse();
    void findTSPSrvCert();

private:
    Q_DISABLE_COPY(SettingsDlg)
};

#endif // SETTINGS_DLG_H
