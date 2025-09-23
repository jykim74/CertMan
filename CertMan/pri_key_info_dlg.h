/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef PRI_KEY_INFO_DLG_H
#define PRI_KEY_INFO_DLG_H

#include "js_bin.h"
#include <QDialog>
#include "ui_pri_key_info_dlg.h"
#include "key_pair_rec.h"
#include "js_pkcs11.h"

class KeyPairRec;

namespace Ui {
class PriKeyInfoDlg;
}

class PriKeyInfoDlg : public QDialog, public Ui::PriKeyInfoDlg
{
    Q_OBJECT

public:
    explicit PriKeyInfoDlg(QWidget *parent = nullptr);
    ~PriKeyInfoDlg();

    void setKeyNum( int key_num );
    void setPrivateKey( const BIN *pPriKey );
    void setPublicKey( const BIN *pPubKey );

private slots:
    void showEvent(QShowEvent *event);

    void changeRSA_N();
    void changeRSA_E( const QString& text );
    void changeRSA_D();
    void changeRSA_P( const QString& text );
    void changeRSA_Q( const QString& text );
    void changeRSA_DMP1( const QString& text );
    void changeRSA_DMQ1( const QString& text );
    void changeRSA_IQMP( const QString& text );

    void changeECC_PubX();
    void changeECC_PubY();
    void changeECC_Private();

    void changeDSA_G();
    void changeDSA_P();
    void changeDSA_Q( const QString& text );
    void changeDSA_Public();
    void changeDSA_Private( const QString& text );

    void changeEdDSA_RawPublic();
    void changeEdDSA_RawPrivate();

    void clickClear();
    void clickGetPrivateKey();
    void clickGetPublicKey();
    void clickInsertToHSM();
    void clickKeyPairCheck();

private:
    void initialize();

    int readPrivateKey();
    int readPrivateKeyHSM();
    void setKey( const BIN *pKey, bool bPri );

    void setRSAKey( const BIN *pKey, bool bPri = true );
    void setECCKey( const BIN *pKey, bool bPri = true );
    void setDSAKey( const BIN *pKey, bool bPri = true );
    void setEdDSAKey( const BIN *pKey, bool bPri = true );

    void setRSAKey( CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setECCKey( CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setDSAKey( CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setEdDSAKey( CK_OBJECT_HANDLE hKey, bool bPri = true );


private:
    int key_num_;
    KeyPairRec key_rec_;
};

#endif // PRI_KEY_INFO_DLG_H
