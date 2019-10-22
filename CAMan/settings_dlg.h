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

    void closeEvent(QCloseEvent *event );
    void showEvent(QShowEvent *event);

private:
    Q_DISABLE_COPY(SettingsDlg)
};

#endif // SETTINGS_DLG_H
