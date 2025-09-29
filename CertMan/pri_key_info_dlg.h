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

    void setKeyNum( int key_num, bool bPri = true );
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

    void changeRawPublic();
    void changeRawPrivate();

    void clickClear();

    void clickInsertToHSM();
    void clickExport();

private:
    void initialize();

    void readPublicKey( KeyPairRec& keyRec );
    int readPrivateKey( KeyPairRec& keyRec );
    int readPrivateKeyHSM( KeyPairRec& keyRec );
    void setKey( const BIN *pKey, bool bPri );

    void setRSAKey( const BIN *pKey, bool bPri = true );
    void setECCKey( const BIN *pKey, bool bPri = true );
    void setDSAKey( const BIN *pKey, bool bPri = true );
    void setRawKey( const BIN *pKey, bool bPri = true );

    void setRSAKey( CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setECCKey( CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setDSAKey( CK_OBJECT_HANDLE hKey, bool bPri = true );
    void setRawKey( CK_OBJECT_HANDLE hKey, bool bPri = true );

    void setEnableRSA_N( bool bVal );
    void setEnableRSA_E( bool bVal );
    void setEnableRSA_D( bool bVal );
    void setEnableRSA_P( bool bVal );
    void setEnableRSA_Q( bool bVal );
    void setEnableRSA_DMP1( bool bVal );
    void setEnableRSA_DMQ1( bool bVal );
    void setEnableRSA_IQMP( bool bVal );

    void setEnableECC_Private( bool bVal );
    void setEnableECC_PubX( bool bVal );
    void setEnableECC_PubY( bool bVal );

    void setEnableDSA_P( bool bVal );
    void setEnableDSA_Q( bool bVal );
    void setEnableDSA_G( bool bVal );
    void setEnableDSA_Private( bool bVal );
    void setEnableDSA_Public( bool bVal );

    void setEnableRawPublic( bool bVal );
    void setEnableRawPrivate( bool bVal );

private:
    int     key_num_;
    bool    is_pri_;
    BIN     key_;
};

#endif // PRI_KEY_INFO_DLG_H
