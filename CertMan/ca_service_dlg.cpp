#include <QLayout>
#include "ca_service_dlg.h"

CAServiceDlg::CAServiceDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CAServiceDlg::~CAServiceDlg()
{

}
