#ifndef SET_PASS_DLG_H
#define SET_PASS_DLG_H

#include <QDialog>
#include "ui_set_pass_dlg.h"

namespace Ui {
class SetPassDlg;
}

class SetPassDlg : public QDialog, public Ui::SetPassDlg
{
    Q_OBJECT

public:
    explicit SetPassDlg(QWidget *parent = nullptr);
    ~SetPassDlg();

    const QString getPasswd() { return mPasswdText->text(); };
    bool usePasswd() { return mUsePasswdCheck->isChecked(); };

private slots:
    virtual void accept();
    void checkUsePasswd();

private:
    void initialize();
};

#endif // SET_PASS_DLG_H
