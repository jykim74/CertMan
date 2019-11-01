#include <QFileDialog>

#include "export_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_pki.h"

ExportDlg::ExportDlg(QWidget *parent) :
    QDialog(parent)
{
    data_num_ = -1;
    data_type_ = -1;

    setupUi(this);

    initUI();
}

ExportDlg::~ExportDlg()
{

}

void ExportDlg::setDataType( int data_type )
{
    data_type_ = data_type;
}

void ExportDlg::setDataNum( int data_num )
{
    data_num_  = data_num;
}

void ExportDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void ExportDlg::accept()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    QString strPath = mPathText->text();

    if( strPath.isEmpty() )
    {
        manApplet->warningBox( tr( "select folder path to save"), this );
        return;
    }

    QDialog::accept();
}

void ExportDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Export Files"),
                                                     "/",
                                                     tr("Cert Files (*.crt);;Key Files (*.key);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    mPathText->setText( fileName );
}

void ExportDlg::initUI()
{
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
}

void ExportDlg::initialize()
{
    QString strMsg;
    QString strPart;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    if( data_type_ == DATA_TYPE_PRIKEY || data_type_ == DATA_TYPE_ENC_PRIKEY || data_type_ == DATA_TYPE_PUBKEY )
    {
        KeyPairRec keyPair;
        dbMgr->getKeyPairRec( data_num_, keyPair );

        if( data_type_ == DATA_TYPE_PRIKEY )
            strMsg = "[Private Key data]\n";
        else if( data_type_ == DATA_TYPE_ENC_PRIKEY )
            strMsg = "[Encrypting Private Key data]\n";
        else if( data_type_ == DATA_TYPE_PUBKEY )
            strMsg = "[Public Key data]\n";

        strPart = QString( "Num: %1\nAlgorithm: %2\nName: %3\n")
                .arg( data_num_)
                .arg( keyPair.getAlg() )
                .arg( keyPair.getName() );
    }
    else if( data_type_ == DATA_TYPE_CERTIFICATE || data_type_ == DATA_TYPE_PFX )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );

        if( data_type_ == DATA_TYPE_CERTIFICATE )
            strMsg = "[ Certificate data ]\n";
        else if( data_type_ == DATA_TYPE_PFX )
            strMsg = "[ PFX data ]\n";

        strPart = QString( "Num: %1\nDN: %2\nAlgorithm: %3\n")
                .arg( data_num_ )
                .arg( cert.getSubjectDN() )
                .arg( cert.getSignAlg() );
    }
    else if( data_type_ == DATA_TYPE_CRL )
    {
        CRLRec crl;
        dbMgr->getCRLRec( data_num_, crl );
        strMsg = "[ CRL data ]\n";

        strPart = QString( "Num: %1\nAlgorithm: %2\n")
                .arg( data_num_ )
                .arg( crl.getSignAlg() );
    }
    else if( data_type_ == DATA_TYPE_REQUEST )
    {
        ReqRec req;
        dbMgr->getReqRec( data_num_, req );
        strMsg = "[ REQUEST data ]\n";

        strPart = QString( "Num: %1\nName: %2\nDN: %3\n")
                .arg(data_num_)
                .arg( req.getName() )
                .arg( req.getDN() );
    }


    if( data_type_ == DATA_TYPE_PFX || data_type_ == DATA_TYPE_ENC_PRIKEY )
    {
        mPasswordText->setEnabled( true );
    }
    else
        mPasswordText->setEnabled( false );

    strMsg += strPart;
    mInfoText->setPlainText( strMsg );
}
