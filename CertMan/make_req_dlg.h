#ifndef MAKE_REQ_DLG_H
#define MAKE_REQ_DLG_H

#include <QDialog>
#include <QList>
#include "ui_make_req_dlg.h"

class KeyPairRec;
class CertProfileRec;

namespace Ui {
class MakeReqDlg;
}

class MakeReqDlg : public QDialog, public Ui::MakeReqDlg
{
    Q_OBJECT

public:
    explicit MakeReqDlg(QWidget *parent = nullptr);
    ~MakeReqDlg();

    void setKeyName( const QString strName );

private slots:
    virtual void accept();
    void keyNameChanged(int index);
    void newAlgChanged(int index );
    void newOptionChanged(int index );
    void checkGenKeyPair();
    void checkExtension();
    void clickMakeDN();

    void clickRSA();
    void clickECDSA();
    void clickDSA();
    void clickEdDSA();

    void checkPKCS11();
    void checkKMIP();

private:
    void initUI();
    void initialize();
    int genKeyPair( KeyPairRec& keyPair );
    const QString getMechanism();

    QList<KeyPairRec> key_list_;
    QList<CertProfileRec> cert_profile_list_;
};

#endif // MAKE_REQ_DLG_H
