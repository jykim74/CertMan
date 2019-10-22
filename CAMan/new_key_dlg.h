#ifndef NEW_KEY_DLG_H
#define NEW_KEY_DLG_H

#include <QDialog>

namespace Ui {
class NewKeyDlg;
}

class NewKeyDlg : public QDialog
{
    Q_OBJECT

public:
    explicit NewKeyDlg(QWidget *parent = nullptr);
    ~NewKeyDlg();

private:
    Ui::NewKeyDlg *ui;
};

#endif // NEW_KEY_DLG_H
