#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "cert_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"


CertInfoDlg::CertInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
    cert_num_ = -1;
}

CertInfoDlg::~CertInfoDlg()
{

}

void CertInfoDlg::setCertNum(int cert_num)
{
    cert_num_ = cert_num;
}

void CertInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CertInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binCert = {0,0};
    JSCertInfo  sCertInfo;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    if( cert_num_ < 0 )
    {
        manApplet->warningBox( tr( "Select certificate"), this );
        this->hide();
        return;
    }

    clearTable();

    CertRec cert;
    dbMgr->getCertRec( cert_num_, cert );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to get certificate information"), this );
        JS_BIN_reset( &binCert );
        this->hide();
        return;
    }

    mBaseTable->insertRow(i);
    mBaseTable->setItem( i, 0, new QTableWidgetItem( QString("Version")));
    mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.nVersion)));
    i++;

    if( sCertInfo.pSerial )
    {
        mBaseTable->insertRow(i);
        mBaseTable->setItem(i, 0, new QTableWidgetItem(QString("Serial")));
        mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSerial)));
        i++;
    }

    mBaseTable->insertRow(i);
    mBaseTable->setItem( i, 0, new QTableWidgetItem( QString("NotBefore")));
    mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.uNotBefore)));
    i++;

    mBaseTable->insertRow(i);
    mBaseTable->setItem( i, 0, new QTableWidgetItem( QString("NotAfter")));
    mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.uNotAfter)));
    i++;

    if( sCertInfo.pSubjectName )
    {
        mBaseTable->insertRow(i);
        mBaseTable->setItem(i, 0, new QTableWidgetItem(QString("SubjectName")));
        mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSubjectName)));
        i++;
    }

    if( sCertInfo.pPublicKey )
    {
        mBaseTable->insertRow(i);
        mBaseTable->setItem(i, 0, new QTableWidgetItem(QString("PublicKey")));
        mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pPublicKey)));
        i++;
    }

    if( sCertInfo.pIssuerName )
    {
        mBaseTable->insertRow(i);
        mBaseTable->setItem(i, 0, new QTableWidgetItem(QString("IssuerName")));
        mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pIssuerName)));
        i++;
    }

    if( sCertInfo.pSignAlgorithm )
    {
        mBaseTable->insertRow(i);
        mBaseTable->setItem(i, 0, new QTableWidgetItem(QString("SigAlgorithm")));
        mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignAlgorithm)));
        i++;
    }

    if( sCertInfo.pSignature )
    {
        mBaseTable->insertRow(i);
        mBaseTable->setItem(i, 0, new QTableWidgetItem(QString("Signature")));
        mBaseTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sCertInfo.pSignature)));
        i++;
    }

    if( sCertInfo.pExtList )
    {
        int k = 0;
        JSExtensionInfoList *pCurList = sCertInfo.pExtList;

        while( pCurList )
        {
            mExtensionTable->insertRow(k);
            mExtensionTable->setItem(k,0, new QTableWidgetItem(QString("%1").arg(pCurList->sExtensionInfo.pOID)));
            mExtensionTable->setItem(k,1, new QTableWidgetItem(QString("%1").arg(pCurList->sExtensionInfo.bCritical)));
            mExtensionTable->setItem(k,2, new QTableWidgetItem(QString("%1").arg(pCurList->sExtensionInfo.pValue)));

            pCurList = pCurList->pNext;
            k++;
        }
    }

    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void CertInfoDlg::initUI()
{
    QStringList sBaseLabels = { tr("Field"), tr("Value") };

    mBaseTable->clear();
    mBaseTable->horizontalHeader()->setStretchLastSection(true);
    mBaseTable->setColumnCount(2);
    mBaseTable->setHorizontalHeaderLabels( sBaseLabels );
    mBaseTable->verticalHeader()->setVisible(false);

    QStringList sExtLabels = { tr("Field"), tr("Critical"), tr("Value") };
    mExtensionTable->clear();
    mExtensionTable->horizontalHeader()->setStretchLastSection(true);
    mExtensionTable->setColumnCount(3);
    mExtensionTable->setHorizontalHeaderLabels(sExtLabels);
    mExtensionTable->verticalHeader()->setVisible(false);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
}

void CertInfoDlg::clickClose()
{
    this->hide();
}

void CertInfoDlg::clearTable()
{
    int rowCnt = mBaseTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mBaseTable->removeRow(0);

    rowCnt = mExtensionTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mExtensionTable->removeRow(0);
}
