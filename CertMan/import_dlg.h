#ifndef IMPORT_DLG_H
#define IMPORT_DLG_H

#include <QDialog>
#include "ui_import_dlg.h"

#include "js_bin.h"

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
    virtual void accept();

    void clickFind();
    void dataTypeChanged( int index );

public slots:
    void setKMIPCheck();

private:
    void initUI();
    void initialize();

    int ImportKeyPair( const BIN *pPriKey );
    int ImportCert( const BIN *pCert );
    int ImportCRL( const BIN *pCRL );
    int ImportRequest( const BIN *pCSR );
    int ImportPFX( const BIN *pPFX );

    int ImportPriKeyToKMIP( int nKeyType, const BIN *pPriKey, int nParam, const BIN *pPubInfoKey, BIN *pID );
    int ImportPriKeyToPKCS11( int nKeyType, const BIN *pPriKey, const BIN *pPubInfoKey, BIN *pID );

private:
};

#endif // IMPORT_DLG_H
