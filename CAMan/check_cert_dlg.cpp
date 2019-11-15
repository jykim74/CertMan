#include "check_cert_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"


CheckCertDlg::CheckCertDlg(QWidget *parent) :
    QDialog(parent)
{
    cert_num_ = -1;
    setupUi(this);
    initUI();
}

CheckCertDlg::~CheckCertDlg()
{

}

void CheckCertDlg::setCertNum( int cert_num )
{
    cert_num_ = cert_num;
}

void CheckCertDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CheckCertDlg::clickClose()
{
    this->hide();
}

void CheckCertDlg::clickView()
{

}

void CheckCertDlg::clickCheck()
{

}

void CheckCertDlg::initUI()
{
    connect( mViewBtn, SIGNAL(clicked()), this, SLOT(clickView() ));
    connect( mCheckBtn, SIGNAL(clicked()), this, SLOT(clickCheck() ));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose() ));
}

void CheckCertDlg::initialize()
{
    cert_list_.clear();

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec cert;

    dbMgr->getCertRec( cert_num_, cert );
    cert_list_.push_front( cert );

    int nIssueNum = cert.getIssuerNum();

    while ( nIssueNum > 0 )
    {
        CertRec parent;
        dbMgr->getCertRec( nIssueNum, parent );
        cert_list_.push_front( parent );

        nIssueNum = parent.getIssuerNum();
    }

    mCertPathTree->clear();
    mCertPathTree->setColumnCount(1);
    QList<QTreeWidgetItem *> items;

    for( int i=0; i < cert_list_.size(); i++ )
    {
        items.append(new QTreeWidgetItem((QTreeWidget*)0, QStringList(QString("item: %1").arg(i))));
    }

    mCertPathTree->insertTopLevelItems(0, items );
}
