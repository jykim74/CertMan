/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef IMPORT_DLG_H
#define IMPORT_DLG_H

#include <QDialog>
#include "ui_import_dlg.h"

#include "js_bin.h"

enum {
    IMPORT_TYPE_PRIKEY = 0,
    IMPORT_TYPE_ENC_PRIKEY,
    IMPORT_TYPE_CSR,
    IMPORT_TYPE_CERT,
    IMPORT_TYPE_CRL,
    IMPORT_TYPE_PFX
};

namespace Ui {
class ImportDlg;
}

class ImportDlg : public QDialog, public Ui::ImportDlg
{
    Q_OBJECT

public:
    explicit ImportDlg(QWidget *parent = nullptr);
    ~ImportDlg();
    void setType( int index );

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);
    virtual void accept();

    void clickFind();
    void dataTypeChanged( int index );

public slots:
    void setKMIPCheck();
    void checkUseFile();
    void changeValue();

private:
    void initUI();
    void initialize();

    int ImportKeyPair( const BIN *pPriKey, int nStatus );
    int ImportCert( const BIN *pCert );
    int ImportCRL( const BIN *pCRL );
    int ImportRequest( const BIN *pCSR );
    int ImportPFX( const BIN *pPFX );

    int ImportPriKeyToKMIP( int nKeyType, const BIN *pPriKey, int nParam, const BIN *pPubInfoKey, BIN *pID );
    int ImportPriKeyToPKCS11( int nKeyType, const BIN *pPriKey, const BIN *pPubInfoKey, BIN *pID );

private:
};

#endif // IMPORT_DLG_H
