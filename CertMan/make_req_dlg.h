#ifndef MAKE_REQ_DLG_H
#define MAKE_REQ_DLG_H

#include <QDialog>
#include <QList>
#include "ui_make_req_dlg.h"

class KeyPairRec;

namespace Ui {
class MakeReqDlg;
}

class MakeReqDlg : public QDialog, public Ui::MakeReqDlg
{
    Q_OBJECT

public:
    explicit MakeReqDlg(QWidget *parent = nullptr);
    ~MakeReqDlg();

private slots:
    virtual void accept();
    void keyNameChanged(int index);
    void newAlgChanged(int index );
    void newOptionChanged(int index );
    void checkGenKeyPair();


private:
    void initUI();
    void initialize();
    int genKeyPair( KeyPairRec& keyPair );

    QList<KeyPairRec> key_list_;

};

#endif // MAKE_REQ_DLG_H
