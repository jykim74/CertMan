#ifndef CSR_INFO_DLG_H
#define CSR_INFO_DLG_H

#include <QDialog>
#include "ui_csr_info_dlg.h"

namespace Ui {
class CSRInfoDlg;
}

class CSRInfoDlg : public QDialog, public Ui::CSRInfoDlg
{
    Q_OBJECT

public:
    explicit CSRInfoDlg(QWidget *parent = nullptr);
    ~CSRInfoDlg();

    void setCSRNum( int nNum );
    int getCSRNum() { return csr_num_; };
    QTableWidgetItem* getExtNameItem( const QString strSN );

private slots:
    void showEvent(QShowEvent *event);

private:
    void initUI();
    void initialize();
    int csr_num_;
};

#endif // CSR_INFO_DLG_H
