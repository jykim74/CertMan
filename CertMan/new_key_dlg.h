#ifndef NEW_KEY_DLG_H
#define NEW_KEY_DLG_H

#include <QDialog>
#include "ui_new_key_dlg.h"
#include "js_bin.h"

namespace Ui {
class NewKeyDlg;
}

class NewKeyDlg : public QDialog, public Ui::NewKeyDlg
{
    Q_OBJECT

public:
    explicit NewKeyDlg(QWidget *parent = nullptr);
    ~NewKeyDlg();

private slots:
    virtual void accept();
    void mechChanged(int index);


private:
    void initUI();
    void initialize();
    int genKeyPairWithP11( QString strPin, BIN *pPri, BIN *pPub );
    int genKeyPairWithKMIP( BIN *pPri, BIN *pPub );

};

#endif // NEW_KEY_DLG_H
