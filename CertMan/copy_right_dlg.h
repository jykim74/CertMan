#ifndef COPY_RIGHT_DLG_H
#define COPY_RIGHT_DLG_H

#include <QDialog>
#include "ui_copy_right_dlg.h"

namespace Ui {
class CopyRightDlg;
}

class CopyRightDlg : public QDialog, public Ui::CopyRightDlg
{
    Q_OBJECT

public:
    explicit CopyRightDlg(QWidget *parent = nullptr);
    ~CopyRightDlg();

    void setURL( const QUrl& url );
private:

};

#endif // COPY_RIGHT_DLG_H
