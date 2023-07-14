#include <QFileDialog>

#include "export_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "commons.h"

#include "js_bin.h"
#include "js_pki.h"
#include "js_pki_tools.h"

static const QStringList kPBEVersions = { "V1", "V2" };

ExportDlg::ExportDlg(QWidget *parent) :
    QDialog(parent)
{
    data_num_ = -1;
    export_type_ = -1;

    setupUi(this);

    connect( mPEMSaveCheck, SIGNAL(clicked()), this, SLOT(clickPEMSaveCheck()));
    connect( mPBEVersionCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changePBEVersion(int)));

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
        QString strAlg;
        KeyPairRec keyPair;
        dbMgr->getKeyPairRec( data_num_, keyPair );

        strAlg = keyPair.getAlg();

        if( export_type_ == EXPORT_TYPE_PRIKEY )
        {
            if( manApplet->isPasswd() )
                manApplet->getDecPriBIN( keyPair.getPrivateKey(), &binData );
            else
                JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binData );

            if( strAlg == "RSA" )
                nPEMType = JS_PEM_TYPE_RSA_PRIVATE_KEY;
            else if( strAlg == "EC" || strAlg == "ECC" )
                nPEMType = JS_PEM_TYPE_EC_PRIVATE_KEY;
            else if( strAlg == "DSA" )
                nPEMType = JS_PEM_TYPE_DSA_PRIVATE_KEY;
            else if( strAlg == "EdDSA" )
                nPEMType = JS_PEM_TYPE_PRIVATE_KEY;
            else
            {
                QString strMsg = tr( "not support algorithm: %1").arg( strAlg );
                manApplet->warningBox( strMsg, this );
                QDialog::reject();
                return;
            }
        }
        else if( export_type_ == EXPORT_TYPE_PUBKEY )
        {
            JS_BIN_decodeHex( keyPair.getPublicKey().toStdString().c_str(), &binData );
            if( strAlg == "RSA" || strAlg == kMechPKCS11_RSA || strAlg == kMechKMIP_RSA )
                nPEMType = JS_PEM_TYPE_RSA_PUBLIC_KEY;
            else if( strAlg == "EC" || strAlg == "ECC" || strAlg == kMechPKCS11_EC || strAlg == kMechKMIP_EC )
                nPEMType = JS_PEM_TYPE_EC_PUBLIC_KEY;
            else if( strAlg == "DSA" || strAlg == kMechPKCS11_DSA )
                nPEMType = JS_PEM_TYPE_DSA_PUBLIC_KEY;
            else if( strAlg == "EdDSA" )
                nPEMType = JS_PEM_TYPE_PUBLIC_KEY;
        }
        else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
        {
            BIN binSrc = {0,0};
            BIN binInfo = {0,0};
            int nPbeNid = -1;
            int nKeyType = -1;

            QString strSN = mPBEAlgCombo->currentText();
            nPbeNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );

            nPEMType = JS_PEM_TYPE_ENCRYPTED_PRIVATE_KEY;

            manApplet->log( QString( "PbeNid: %1 (%2)").arg( strSN ).arg( nPbeNid ));

            if( manApplet->isPasswd() )
                manApplet->getDecPriBIN( keyPair.getPrivateKey(), &binSrc );
            else
                JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binSrc );

            if( strAlg == "RSA" )
            {
                nKeyType = JS_PKI_KEY_TYPE_RSA;
            }
            else if( strAlg == "EC" )
            {
                nKeyType = JS_PKI_KEY_TYPE_ECC;
            }
            else if( strAlg == "DSA" )
            {
                nKeyType = JS_PKI_KEY_TYPE_DSA;
            }
            else if( strAlg == "EdDSA" )
            {
                nKeyType = JS_PKI_KEY_TYPE_ED25519;

                if( keyPair.getParam() == "Ed448" )
                    nKeyType = JS_PKI_KEY_TYPE_ED448;
            }
            else
            {
                manApplet->warningBox( QString( "Not support %1 algorithm to export").arg( keyPair.getAlg()));
                ret = -1;
                return;
            }

            ret = JS_PKI_encryptPrivateKey( nKeyType, nPbeNid, strPass.toStdString().c_str(), &binSrc, &binInfo, &binData );

            JS_BIN_reset( &binSrc );
            JS_BIN_reset( &binInfo );

            if( ret != 0 )
            {
                manApplet->warningBox( tr( "fail to encrypt private key"), this );
                QDialog::reject();
                return;
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
        QString strAlg;

        BIN binPri = {0,0};
        BIN binCert = { 0, 0};

        QString strSN = mPBEAlgCombo->currentText();
        int nPbeNid = JS_PKI_getNidFromSN( strSN.toStdString().c_str() );

        manApplet->log( QString( "PbeNid: %1 (%2)").arg( strSN ).arg( nPbeNid ));

        dbMgr->getCertRec( data_num_, cert );
        dbMgr->getKeyPairRec( cert.getKeyNum(), keyPair );

        strAlg = keyPair.getAlg();

        if( strAlg == kMechRSA )
            nKeyType = JS_PKI_KEY_TYPE_RSA;
        else if( strAlg == kMechEC )
            nKeyType = JS_PKI_KEY_TYPE_ECC;
        else if( strAlg == kMechDSA )
            nKeyType = JS_PKI_KEY_TYPE_DSA;
        else if( strAlg == kMechEdDSA )
        {
            nKeyType = JS_PKI_KEY_TYPE_ED25519;
            if( keyPair.getParam() == kMechEd448 )
                nKeyType = JS_PKI_KEY_TYPE_ED448;
        }
        else
        {
            QString strMsg = tr( "not support algorithm: %1").arg( strAlg );
            manApplet->warningBox( strMsg, this );
            QDialog::reject();
            return;
        }

        if( manApplet->isPasswd() )
            manApplet->getDecPriBIN( keyPair.getPrivateKey(), &binPri );
        else
            JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

        JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

        ret = JS_PKI_encodePFX( &binData, nKeyType, strPass.toStdString().c_str(), nPbeNid, &binPri, &binCert );

        JS_BIN_reset( &binPri );
        JS_BIN_reset( &binCert );

        if( ret != 0 )
        {
            QString strMsg = tr( "fail to encode PFX: %1" ).arg(ret);
            manApplet->warningBox( strMsg, this );
            manApplet->elog( strMsg );

            QDialog::reject();
            return;
        }
    }

    if( mPEMSaveCheck->isChecked() )
        JS_BIN_writePEM( &binData, nPEMType, strPath.toLocal8Bit().toStdString().c_str() );
    else
        JS_BIN_fileWrite( &binData, strPath.toLocal8Bit().toStdString().c_str() );

    manApplet->setCurFile( strPath );

    JS_BIN_reset( &binData );

    manApplet->messageBox( tr("Export successfully"), this );
    QDialog::accept();
}

void ExportDlg::clickFind()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strFilter;
    QString strPath = mPathText->text();

    if( strPath.length() < 1 )
        strPath = manApplet->curFile();

    if( export_type_ == EXPORT_TYPE_PRIKEY )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("Key Files (*.key);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_PUBKEY )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_REQUEST )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("CSR Files (*.csr);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_CRL )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("CRL Files (*.crl);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_PFX )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("PFX Files (*.pfx);;DER Files (*.der);;All Files (*.*)");
    }
    else if( export_type_ == EXPORT_TYPE_CERTIFICATE )
    {
        if( mPEMSaveCheck->isChecked() )
            strFilter = tr("Cert Files (*.crt);;PEM Files (*.pem);;All Files (*.*)");
        else
            strFilter = tr("Cert Files (*.crt);;DER Files (*.der);;All Files (*.*)");
    }

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Export Files"),
                                                     strPath,
                                                     strFilter,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() > 0 )
    {
        mPathText->setText( fileName );
    }
}

void ExportDlg::clickPEMSaveCheck()
{
    bool bStatus = mPEMSaveCheck->isChecked();
    QString strPath = mPathText->text();

    QFileInfo file;
    file.setFile( strPath );

    QString fileName = file.fileName();

    QStringList nameList = fileName.split( "." );
    QString strPathName;
    QString strExt;

    int num = nameList.size();

    if( num == 2 || num == 1 )
    {
        strPathName = nameList.at(0);
        strPathName += ".";
    }
    else if( num == 0 )
    {
        strPathName = "undefined.";
    }
    else
    {
        manApplet->warningBox( "Invalid Path Name", this );
        return;
    }


    if( bStatus )
    {
        strExt = "pem";
    }
    else
    {
        strExt = "der";
    }

    strPathName += strExt;
    mPathText->setText( file.dir().path() + "/" + strPathName );
}

void ExportDlg::changePBEVersion( int index )
{
    mPBEAlgCombo->clear();

    if( index == 0 )
        mPBEAlgCombo->addItems( kPBEv1List );
    else
        mPBEAlgCombo->addItems( kPBEv2List );
}

void ExportDlg::initUI()
{
    connect( mFindBtn, SIGNAL(clicked()), this, SLOT(clickFind()));
    mPasswordText->setEchoMode(QLineEdit::Password);

    mPBEVersionCombo->addItems( kPBEVersions );
    mPBEAlgCombo->clear();
    mPBEAlgCombo->addItems( kPBEv1List );
}

void ExportDlg::initialize()
{
    QString strPath;
    QString strLabel;
    QString strName;
    QString strInfo;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( data_num_ < 0 || export_type_ < 0 )
    {
        manApplet->warningBox( tr( "There is no data to be selected" ), this );
        return;
    }

    if( export_type_ == EXPORT_TYPE_PRIKEY || export_type_ == EXPORT_TYPE_ENC_PRIKEY || export_type_ == EXPORT_TYPE_PUBKEY )
    {
        KeyPairRec keyPair;
        dbMgr->getKeyPairRec( data_num_, keyPair );

        strPath = keyPair.getName();

        if( export_type_ == EXPORT_TYPE_PRIKEY )
        {
            strLabel = "Export PrivateKey";
            strPath += "_pri.der";
        }
        else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
        {
            mPasswordText->setEnabled(true);
            strLabel = "Export Encrypted PrivateKey";
            strPath += "_enc_pri.key";
        }
        else if( export_type_ == EXPORT_TYPE_PUBKEY )
        {
            strLabel = "Export PublicKey";
            strPath += "_pub.der";
        }

        strName = keyPair.getName();
        strInfo = QString( "Num       : %1\n"
                           "Algorithm : %2\n" ).arg( data_num_ ).arg( keyPair.getAlg() );

    }
    else if( export_type_ == EXPORT_TYPE_CERTIFICATE || export_type_ == EXPORT_TYPE_PFX )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );

        strPath = getNameFromDN( cert.getSubjectDN() );

        if( export_type_ == EXPORT_TYPE_CERTIFICATE )
        {
            strLabel = "Export Certificate";
            strPath += "_cert.der";
        }
        else if( export_type_ == EXPORT_TYPE_PFX )
        {
            mPasswordText->setEnabled(true);
            strLabel = "Export PFX";
            strPath += ".pfx";
        }

        strName = cert.getSubjectDN();
        strInfo = QString( "Num       : %1\n"
                           "Algorithm : %2\n")
                .arg( data_num_ )
                .arg( cert.getSignAlg() );
    }
    else if( export_type_ == EXPORT_TYPE_CRL )
    {
        CRLRec crl;
        CertRec issuer;

        dbMgr->getCRLRec( data_num_, crl );

        if( crl.getIssuerNum() > 0 )
        {
            dbMgr->getCertRec( crl.getIssuerNum(), issuer );
            strName = issuer.getSubjectDN();
        }
        else
        {
            strName = "Unknown";
        }


        strLabel = "Export CRL";
 //       strName = crl.getCRLDP();
        strPath = getNameFromDN( strName );

        strInfo = QString( "Num       : %1\n"
                           "Algorithm : %2\n"
                           "CRLDP     : %3\n" )
                .arg( data_num_ )
                .arg( crl.getSignAlg() )
                .arg( crl.getCRLDP() );

        strPath += "_crl.crl";
    }
    else if( export_type_ == EXPORT_TYPE_REQUEST )
    {
        ReqRec req;
        dbMgr->getReqRec( data_num_, req );

        strLabel = "Export CSR";
        strName = req.getName();
        strPath = strName;

        strInfo = QString( "Num : %1\n"
                           "DN  : %2\n")
                .arg(data_num_)
                .arg( req.getDN() );

        strPath += "_req.der";
    }


    if( export_type_ == EXPORT_TYPE_PFX || export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        mEncGroup->setEnabled( true );
    }
    else
        mEncGroup->setEnabled( false );

    if( exportType() == EXPORT_TYPE_PFX )
    {
        mPEMSaveCheck->setChecked(false);
        mPEMSaveCheck->setEnabled(false);
    }
    else
        mPEMSaveCheck->setEnabled(true);

    mExportLabel->setText( strLabel );
    mNameText->setText( strName );
    mInfoText->setPlainText( strInfo );
    mPathText->setText( manApplet->curFolder() + "/" + strPath );
}
