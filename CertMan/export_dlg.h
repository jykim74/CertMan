/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef EXPORT_DLG_H
#define EXPORT_DLG_H

#include <QDialog>
#include "ui_export_dlg.h"
#include "js_bin.h"

namespace Ui {
class ExportDlg;
}

enum {
    DataPriKey = 1,
    DataPubKey,
    DataCert,
    DataCRL,
    DataCSR,
    DataPriKeyCert,
};

enum {
    ExportPubPEM = 1,   // PEM public (*.pem)
    ExportPubDER,       // DER public (*.der)
    ExportPriPEM,       // PEM private (*.pem)
    ExportPriDER,       // DER private (*.der)
    ExportCertPEM,      // PEM certificate (*.crt)
    ExportCertDER,      // DER certificate (*.cer)
    ExportPFX,          // PKCS12 (*.pfx)
    ExportP8InfoPEM,    // PEM PKCS8 Info (*.pk8)
    ExportP8InfoDER,    // DER PKCS8 Info (*.der)
    ExportP8EncPEM,     // PEM PKCS8 Encrypt (*.key)
    ExportP8EncDER,     // DER PKCS8 Encrypt (*.der)
    ExportCSR_PEM,      // PEM CSR (*.csr)
    ExportCSR_DER,      // DER CSR (*.der)
    ExportCRL_PEM,      // PEM CRL (*.crl)
    ExportCRL_DER,      // DER CRL (*.der)
    ExportChain_PEM,    // PEM Chain (*.pem)
    ExportFullChain_PEM // PEM Full Chain (*.pem)
};


enum {
    EXPORT_TYPE_PRIKEY = 1,
    EXPORT_TYPE_INFO_PRIKEY,
    EXPORT_TYPE_ENC_PRIKEY,
    EXPORT_TYPE_PUBKEY,
    EXPORT_TYPE_REQUEST,
    EXPORT_TYPE_CERTIFICATE,
    EXPORT_TYPE_CRL,
    EXPORT_TYPE_PFX,
    EXPORT_TYPE_CHAIN,
    EXPORT_TYPE_FULL_CHAIN
};

class ExportDlg : public QDialog, public Ui::ExportDlg
{
    Q_OBJECT

public:
    explicit ExportDlg(QWidget *parent = nullptr);
    ~ExportDlg();

    void setName( const QString strName );

    void setPrivateKey( const BIN *pPriKey );
    void setPublicKey( const BIN *pPubKey );
    void setCert( const BIN *pCert );
    void setCRL( const BIN *pCRL );
    void setCSR( const BIN *pCSR );
    void setPriKeyAndCert( int nDataNum, const BIN *pPriKey, const BIN *pCert );

private slots:

    void changeFormatType( int index );
    void clickOK();
    void clickFindPath();

private:
    void initUI();
    void initialize();

    int exportPublic();
    int exportPrivate();
    int exportCert();
    int exportCRL();
    int exportCSR();
    int exportPFX();
    int exportP8Enc();
    int exportP8Info();
    int exportChain( bool bFull = false );

private:
    int data_num_;

    BIN data_;
    BIN data2_;

    int data_type_;
    int key_type_;
};

#endif // EXPORT_DLG_H
