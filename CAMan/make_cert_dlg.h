#ifndef MAKE_CERT_DLG_H
#define MAKE_CERT_DLG_H

#include <QDialog>

namespace Ui {
class MakeCertDlg;
}

class MakeCertDlg : public QDialog
{
    Q_OBJECT

public:
    explicit MakeCertDlg(QWidget *parent = nullptr);
    ~MakeCertDlg();

private:
    Ui::MakeCertDlg *ui;
};

#endif // MAKE_CERT_DLG_H
