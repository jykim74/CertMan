#include "check_cert_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_bin.h"
#include "js_pki.h"

CheckCertDlg::CheckCertDlg(QWidget *parent) :
    QDialog(parent)
{
    cert_num_ = -1;
    setupUi(this);
    initUI();
    initialize();
}

CheckCertDlg::~CheckCertDlg()
{

}

void CheckCertDlg::setCertNum( int cert_num )
{
    cert_num_ = cert_num;
}


void CheckCertDlg::clickClose()
{
    this->hide();
}

void CheckCertDlg::clickView()
{
    manApplet->mainWindow()->viewCertificate();
}

void CheckCertDlg::clickCheck()
{
    int ret = 0;
    BINList *pChainList = NULL;
    BIN     binCert = {0,0};

    for( int i = 0; i < cert_list_.size(); i++ )
    {
        CertRec cert = cert_list_.at(i);

        if( i == cert_list_.size() - 1 )
        {
            JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );
        }
        else
        {
            BIN bin = {0,0};
            JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &bin );

            if( pChainList == NULL )
                JS_BIN_createList( &bin, &pChainList );
            else
                JS_BIN_appendList( pChainList, &bin );

            JS_BIN_reset( &bin );
        }
    }

    ret = JS_PKI_checkValidPath( pChainList, NULL, &binCert );

    QString strRes = QString( "Ret: %1").arg( ret );
    mCertInfoText->setText( strRes );

    if( pChainList ) JS_BIN_resetList( &pChainList );
    JS_BIN_reset( &binCert );
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
    QTreeWidgetItem* pPrevItem = NULL;

    for( int i=0; i < cert_list_.size(); i++ )
    {
        CertRec cert = cert_list_.at(i);
        QTreeWidgetItem *item = new QTreeWidgetItem( 0 );
        item->setText( 0, cert.getSubjectDN() );

        if( i == 0 )
            mCertPathTree->insertTopLevelItem(0, item );
        else
        {
            pPrevItem->addChild( item );
        }

        pPrevItem = item;
    }
}
