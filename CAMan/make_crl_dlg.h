#ifndef MAKE_CRL_DLG_H
#define MAKE_CRL_DLG_H

#include <QDialog>

namespace Ui {
class MakeCRLDlg;
}

class MakeCRLDlg : public QDialog
{
    Q_OBJECT

public:
    explicit MakeCRLDlg(QWidget *parent = nullptr);
    ~MakeCRLDlg();

private:
    Ui::MakeCRLDlg *ui;
};

#endif // MAKE_CRL_DLG_H
