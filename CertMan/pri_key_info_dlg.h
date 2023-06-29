#ifndef PRI_KEY_INFO_DLG_H
#define PRI_KEY_INFO_DLG_H

#include "js_bin.h"
#include <QDialog>
#include "ui_pri_key_info_dlg.h"

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

private slots:
    void showEvent(QShowEvent *event);

    void changeRSA_N( const QString& text );
    void changeRSA_E( const QString& text );
    void changeRSA_D( const QString& text );
    void changeRSA_P( const QString& text );
    void changeRSA_Q( const QString& text );
    void changeRSA_DMP1( const QString& text );
    void changeRSA_DMQ1( const QString& text );
    void changeRSA_IQMP( const QString& text );

    void changeECC_Group( const QString& text );
    void changeECC_PubX( const QString& text );
    void changeECC_PubY( const QString& text );
    void changeECC_Private( const QString& text );

    void changeDSA_G( const QString& text );
    void changeDSA_P( const QString& text );
    void changeDSA_Q( const QString& text );
    void changeDSA_Private( const QString& text );

    void changeEdDSA_RawPublic( const QString& text );
    void changeEdDSA_RawPrivate( const QString& text );

private:
    void initialize();

    void setRSAPriKey( const BIN *pPriKey );
    void setECCPriKey( const BIN *pPriKey );
    void setDSAPriKey( const BIN *pPriKey );
    void setEdDSAPriKey( const BIN *pPriKey );

private:
    int key_num_;
};

#endif // PRI_KEY_INFO_DLG_H
