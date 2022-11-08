#include <QFileDialog>

#include "export_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_bin.h"
#include "js_pki.h"

ExportDlg::ExportDlg(QWidget *parent) :
    QDialog(parent)
{
    data_num_ = -1;
    export_type_ = -1;

    setupUi(this);

    initUI();
}

ExportDlg::~ExportDlg()
{

}

void ExportDlg::setExportType( int export_type )
{
    export_type_ = export_type;
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
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    QString strPass = mPasswordText->text();
    QString strPath = mPathText->text();

    int nPEMType = -1;

    if( strPath.isEmpty() )
    {
        manApplet->warningBox( tr( "select folder path to save"), this );
        return;
    }

    if( export_type_ == EXPORT_TYPE_PFX || export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        if( strPass.isEmpty() )
        {
            manApplet->warningBox( tr("insert password" ), this );
            mPasswordText->setFocus();
            return;
        }
    }

    BIN binData = {0,0};

    if( export_type_ == EXPORT_TYPE_PRIKEY || export_type_ == EXPORT_TYPE_ENC_PRIKEY || export_type_ == EXPORT_TYPE_PUBKEY )
    {
        KeyPairRec keyPair;
        dbMgr->getKeyPairRec( data_num_, keyPair );

        if( export_type_ == EXPORT_TYPE_PRIKEY )
        {
            JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binData );
            if( keyPair.getAlg() == "RSA" )
                nPEMType = JS_PEM_TYPE_RSA_PRIVATE_KEY;
            else
                nPEMType = JS_PEM_TYPE_EC_PRIVATE_KEY;
        }
        else if( export_type_ == EXPORT_TYPE_PUBKEY )
        {
            JS_BIN_decodeHex( keyPair.getPublicKey().toStdString().c_str(), &binData );
            if( keyPair.getAlg() == "RSA" )
                nPEMType = JS_PEM_TYPE_RSA_PUBLIC_KEY;
            else
                nPEMType = JS_PEM_TYPE_EC_PUBLIC_KEY;
        }
        else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
        {
            BIN binSrc = {0,0};
            BIN binInfo = {0,0};

            JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binSrc );
            if( keyPair.getAlg() == "RSA" )
            {
                ret = JS_PKI_encryptRSAPrivateKey( -1, strPass.toStdString().c_str(), &binSrc, &binInfo, &binData );
            }
            else if( keyPair.getAlg() == "EC" )
            {
                ret = JS_PKI_encryptECPrivateKey( -1, strPass.toStdString().c_str(), &binSrc, &binInfo, &binData );
            }

            JS_BIN_reset( &binSrc );
            JS_BIN_reset( &binInfo );

            if( ret != 0 )
            {
                manApplet->warningBox( tr( "fail to encrypt private key"), this );
                QDialog::reject();
            }
        }
    }
    else if( export_type_ == EXPORT_TYPE_CERTIFICATE )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );
        JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binData );
        nPEMType = JS_PEM_TYPE_CERTIFICATE;
    }
    else if( export_type_ == EXPORT_TYPE_CRL )
    {
        CRLRec crl;
        dbMgr->getCRLRec( data_num_, crl );
        JS_BIN_decodeHex( crl.getCRL().toStdString().c_str(), &binData );
        nPEMType = JS_PEM_TYPE_CRL;
    }
    else if( export_type_ == EXPORT_TYPE_REQUEST )
    {
        ReqRec req;
        dbMgr->getReqRec( data_num_, req );
        JS_BIN_decodeHex( req.getCSR().toStdString().c_str(), &binData );
        nPEMType = JS_PEM_TYPE_CSR;
    }
    else if( export_type_ == EXPORT_TYPE_PFX )
    {
        int nKeyType = -1;
        KeyPairRec keyPair;
        CertRec cert;

        BIN binPri = {0,0};
        BIN binCert = { 0, 0};

        dbMgr->getCertRec( data_num_, cert );
        dbMgr->getKeyPairRec( cert.getKeyNum(), keyPair );
        if( keyPair.getAlg() == "RSA" )
            nKeyType = JS_PKI_KEY_TYPE_RSA;
        else if( keyPair.getAlg() == "EC" )
            nKeyType == JS_PKI_KEY_TYPE_ECC;

        JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );
        JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

        JS_PKI_encodePFX( &binData, nKeyType, strPass.toStdString().c_str(), &binPri, &binCert );

        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binCert );
    }

    if( mPEMSaveCheck->isChecked() )
        JS_BIN_writePEM( &binData, nPEMType, strPath.toStdString().c_str() );
    else
        JS_BIN_fileWrite( &binData, strPath.toLocal8Bit().toStdString().c_str() );

    JS_BIN_reset( &binData );
    QDialog::accept();
}

void ExportDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter;
    QString strPath = mPathText->text();

    if( export_type_ == EXPORT_TYPE_PRIKEY )
    {
        strFilter = tr("DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        strFilter = tr("Key Files (*.key);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_PUBKEY )
    {
        strFilter = tr("DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_REQUEST )
    {
        strFilter = tr("CSR Files (*.csr);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_CRL )
    {
        strFilter = tr("CRL Files (*.crl);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_PFX )
    {
        strFilter = tr("PFX Files (*.pfx);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_CERTIFICATE )
    {
        strFilter = tr("Cert Files (*.crt);;DER Files (*.der);;All Files (*.*)");
    }

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Export Files"),
                                                     strPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() > 0 ) mPathText->setText( fileName );
}

void ExportDlg::initUI()
{
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
    mPasswordText->setEchoMode(QLineEdit::Password);
}

void ExportDlg::initialize()
{
    QString strMsg;
    QString strPart;
    QString strPath;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( data_num_ < 0 || export_type_ < 0 )
    {
        manApplet->warningBox( tr( "There is no data to be selected" ));
        return;
    }

    if( export_type_ == EXPORT_TYPE_PRIKEY || export_type_ == EXPORT_TYPE_ENC_PRIKEY || export_type_ == EXPORT_TYPE_PUBKEY )
    {
        KeyPairRec keyPair;
        dbMgr->getKeyPairRec( data_num_, keyPair );

        if( export_type_ == EXPORT_TYPE_PRIKEY )
        {
            strMsg = "[Private Key data]\n";
            strPath = "pri.der";
        }
        else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
        {
            mPasswordText->setEnabled(true);
            strMsg = "[Encrypting Private Key data]\n";
            strPath = "pri.key";
        }
        else if( export_type_ == EXPORT_TYPE_PUBKEY )
        {
            strMsg = "[Public Key data]\n";
            strPath = "pub.der";
        }

        strPart = QString( "Num: %1\nAlgorithm: %2\nName: %3\n")
                .arg( data_num_)
                .arg( keyPair.getAlg() )
                .arg( keyPair.getName() );
    }
    else if( export_type_ == EXPORT_TYPE_CERTIFICATE || export_type_ == EXPORT_TYPE_PFX )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );

        if( export_type_ == EXPORT_TYPE_CERTIFICATE )
        {
            strMsg = "[ Certificate data ]\n";
            strPath = "cert.der";
        }
        else if( export_type_ == EXPORT_TYPE_PFX )
        {
            mPasswordText->setEnabled(true);
            strMsg = "[ PFX data ]\n";
            strPath = "pri_pub_cert.pfx";
        }

        strPart = QString( "Num: %1\nDN: %2\nAlgorithm: %3\n")
                .arg( data_num_ )
                .arg( cert.getSubjectDN() )
                .arg( cert.getSignAlg() );
    }
    else if( export_type_ == EXPORT_TYPE_CRL )
    {
        CRLRec crl;
        dbMgr->getCRLRec( data_num_, crl );
        strMsg = "[ CRL data ]\n";

        strPart = QString( "Num: %1\nAlgorithm: %2\n")
                .arg( data_num_ )
                .arg( crl.getSignAlg() );

        strPath = "crl.der";
    }
    else if( export_type_ == EXPORT_TYPE_REQUEST )
    {
        ReqRec req;
        dbMgr->getReqRec( data_num_, req );
        strMsg = "[ REQUEST data ]\n";

        strPart = QString( "Num: %1\nName: %2\nDN: %3\n")
                .arg(data_num_)
                .arg( req.getName() )
                .arg( req.getDN() );

        strPath = "req.der";
    }


    if( export_type_ == EXPORT_TYPE_PFX || export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        mPasswordText->setEnabled( true );
    }
    else
        mPasswordText->setEnabled( false );

    if( exportType() == EXPORT_TYPE_PFX )
    {
        mPEMSaveCheck->setChecked(false);
        mPEMSaveCheck->setEnabled(false);
    }
    else
        mPEMSaveCheck->setEnabled(true);

    strMsg += strPart;
    mInfoText->setPlainText( strMsg );
    mPathText->setText( strPath );
}
