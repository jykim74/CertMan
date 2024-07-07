/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>

#include "export_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "commons.h"

#include "js_error.h"
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

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(width(), minimumSizeHint().height());
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

    if( export_type_ == EXPORT_TYPE_FULL_CHAIN || export_type_ == EXPORT_TYPE_CHAIN )
        ret = saveChain();
    else
        ret = saveData();

    if( ret == JSR_OK )
    {
        manApplet->messageBox( tr("Export was successful"), this );
        QDialog::accept();
    }
}

int ExportDlg::saveData()
{
    int ret = 0;
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return JSR_ERR;

    QString strPass = mPasswordText->text();
    QString strPath = mPathText->text();

    int nPEMType = -1;

    if( strPath.isEmpty() )
    {
        manApplet->warningBox( tr( "select a directory to save"), this );
        return JSR_ERR;
    }

    if( export_type_ == EXPORT_TYPE_PFX || export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        if( strPass.isEmpty() )
        {
            manApplet->warningBox( tr("Please enter a password" ), this );
            mPasswordText->setFocus();
            return JSR_ERR;
        }
    }

    BIN binData = {0,0};

    if( export_type_ == EXPORT_TYPE_PRIKEY || export_type_ == EXPORT_TYPE_ENC_PRIKEY
        || export_type_ == EXPORT_TYPE_PUBKEY || export_type_ == EXPORT_TYPE_INFO_PRIKEY )
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

            if( strAlg == kMechRSA )
                nPEMType = JS_PEM_TYPE_RSA_PRIVATE_KEY;
            else if( strAlg == kMechEC )
                nPEMType = JS_PEM_TYPE_EC_PRIVATE_KEY;
            else if( strAlg == kMechDSA )
                nPEMType = JS_PEM_TYPE_DSA_PRIVATE_KEY;
            else if( strAlg == kMechEdDSA )
                nPEMType = JS_PEM_TYPE_PRIVATE_KEY;
            else
            {
                QString strMsg = tr( "This algorithm [%1] is not supported").arg( strAlg );
                manApplet->warningBox( strMsg, this );
                QDialog::reject();
                return JSR_ERR;;
            }
        }
        else if( export_type_ == EXPORT_TYPE_INFO_PRIKEY )
        {
            int nKeyType = -1;
            BIN binSrc = {0,0};

            if( manApplet->isPasswd() )
                manApplet->getDecPriBIN( keyPair.getPrivateKey(), &binSrc );
            else
                JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binSrc );

            if( strAlg == kMechRSA )
            {
                nKeyType = JS_PKI_KEY_TYPE_RSA;
            }
            else if( strAlg == kMechEC )
            {
                nKeyType = JS_PKI_KEY_TYPE_ECC;
            }
            else if( strAlg == kMechDSA )
            {
                nKeyType = JS_PKI_KEY_TYPE_DSA;
            }
            else if( strAlg == kMechEdDSA )
            {
                nKeyType = JS_PKI_KEY_TYPE_ED25519;

                if( keyPair.getParam() == "Ed448" )
                    nKeyType = JS_PKI_KEY_TYPE_ED448;
            }
            else
            {
                manApplet->warningBox( QString( "This algorithm [%1] is not supported").arg( keyPair.getAlg()));
                JS_BIN_reset( &binSrc );
                ret = -1;
                return JSR_ERR;;
            }

            ret = JS_PKI_encodePrivateKeyInfo( nKeyType, &binSrc, &binData );

            JS_BIN_reset( &binSrc );

            if( ret != 0 )
            {
                manApplet->warningBox( tr( "failed to encrypt the private key [%1]").arg(ret), this );
                QDialog::reject();
                return JSR_ERR;;
            }
        }
        else if( export_type_ == EXPORT_TYPE_PUBKEY )
        {
            JS_BIN_decodeHex( keyPair.getPublicKey().toStdString().c_str(), &binData );
            if( strAlg == kMechRSA || strAlg == kMechPKCS11_RSA || strAlg == kMechKMIP_RSA )
                nPEMType = JS_PEM_TYPE_RSA_PUBLIC_KEY;
            else if( strAlg == kMechEC || strAlg == kMechPKCS11_EC || strAlg == kMechKMIP_EC )
                nPEMType = JS_PEM_TYPE_EC_PUBLIC_KEY;
            else if( strAlg == kMechDSA || strAlg == kMechPKCS11_DSA )
                nPEMType = JS_PEM_TYPE_DSA_PUBLIC_KEY;
            else if( strAlg == kMechEdDSA )
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

            if( strAlg == kMechRSA )
            {
                nKeyType = JS_PKI_KEY_TYPE_RSA;
            }
            else if( strAlg == kMechEC )
            {
                nKeyType = JS_PKI_KEY_TYPE_ECC;
            }
            else if( strAlg == kMechDSA )
            {
                nKeyType = JS_PKI_KEY_TYPE_DSA;
            }
            else if( strAlg == kMechEdDSA )
            {
                nKeyType = JS_PKI_KEY_TYPE_ED25519;

                if( keyPair.getParam() == "Ed448" )
                    nKeyType = JS_PKI_KEY_TYPE_ED448;
            }
            else
            {
                manApplet->warningBox( QString( "This algorithm [%1] is not supported").arg( keyPair.getAlg()));
                ret = -1;
                return JSR_ERR;;
            }

            ret = JS_PKI_encryptPrivateKey( nKeyType, nPbeNid, strPass.toStdString().c_str(), &binSrc, &binInfo, &binData );

            JS_BIN_reset( &binSrc );
            JS_BIN_reset( &binInfo );

            if( ret != 0 )
            {
                manApplet->warningBox( tr( "failed to encrypt the private key [%1]").arg(ret), this );
                return JSR_ERR;;
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
            QString strMsg = tr( "This algorithm [%1] is not supported").arg( strAlg );
            manApplet->warningBox( strMsg, this );return JSR_ERR;
            return JSR_ERR;
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
            QString strMsg = tr( "failed to create PFX file [%1]" ).arg(ret);
            manApplet->warningBox( strMsg, this );
            manApplet->elog( strMsg );

            return JSR_ERR;;
        }
    }

    if( mPEMSaveCheck->isChecked() && export_type_ != EXPORT_TYPE_PFX)
        JS_BIN_writePEM( &binData, nPEMType, strPath.toLocal8Bit().toStdString().c_str() );
    else
        JS_BIN_fileWrite( &binData, strPath.toLocal8Bit().toStdString().c_str() );

    manApplet->setCurFile( strPath );

    JS_BIN_reset( &binData );

    return JSR_OK;
}

int ExportDlg::saveChain()
{
    QList<CertRec> certList;
    int nSize = 0;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return JSR_ERR;

    QString strPath = mPathText->text();

    CertRec cert;

    dbMgr->getCertRec( data_num_, cert );
    certList.push_front( cert );

    int nIssueNum = cert.getIssuerNum();

    while ( nIssueNum > 0 )
    {
        CertRec parent;
        dbMgr->getCertRec( nIssueNum, parent );
        certList.push_front( parent );

        nIssueNum = parent.getIssuerNum();
    }

    if( export_type_ == EXPORT_TYPE_FULL_CHAIN )
    {
        nSize = certList.size();
    }
    else if( export_type_ == EXPORT_TYPE_CHAIN )
    {
        nSize = certList.size() - 1;
    }

    for( int i = 0; i < nSize; i++ )
    {
        int nType = JS_PEM_TYPE_CERTIFICATE;
        BIN binCert = {0,0};
        CertRec cert = certList.at(i);

        JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );
        JS_BIN_appendPEM( &binCert, nType, strPath.toLocal8Bit().toStdString().c_str() );
        JS_BIN_reset( &binCert );
    }

    return 0;
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
        manApplet->warningBox( "Invalid directory name", this );
        return;
    }


    if( bStatus )
    {
        strExt = "pem";
    }
    else
    {
        if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
            strExt = "key";
        else
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
        manApplet->warningBox( tr( "No data selected" ), this );
        return;
    }

    if( export_type_ == EXPORT_TYPE_PRIKEY || export_type_ == EXPORT_TYPE_ENC_PRIKEY
        || export_type_ == EXPORT_TYPE_PUBKEY || export_type_ == EXPORT_TYPE_INFO_PRIKEY )
    {
        KeyPairRec keyPair;
        dbMgr->getKeyPairRec( data_num_, keyPair );

        strPath = keyPair.getName();

        if( export_type_ == EXPORT_TYPE_PRIKEY )
        {
            strLabel = "Export private key";
            strPath += "_pri.der";
        }
        else if( export_type_ == EXPORT_TYPE_ENC_PRIKEY )
        {
            mPasswordText->setEnabled(true);
            strLabel = "Export encrypted private key";
            strPath += "_enc_pri.key";
        }
        else if( export_type_ == EXPORT_TYPE_PUBKEY )
        {
            strLabel = "Export public key";
            strPath += "_pub.der";
        }
        else if( export_type_ == EXPORT_TYPE_INFO_PRIKEY )
        {
            strLabel = "Export private key info";
            strPath += "_p8_info.der";
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
            strLabel = "Export certificate";
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
    else if( export_type_ == EXPORT_TYPE_CHAIN )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );

        if( cert.getIssuerNum() < 0 )
        {
            manApplet->warningBox( tr( "There is no issuer certifiate." ), this );
            return;
        }

        strPath = getNameFromDN( cert.getSubjectDN() );

        strLabel = "Export chain";
        strPath += "_chain.pem";

        strName = cert.getSubjectDN();
        strInfo = QString( "Num       : %1\n"
                          "Algorithm : %2\n")
                      .arg( data_num_ )
                      .arg( cert.getSignAlg() );

    }
    else if( export_type_ == EXPORT_TYPE_FULL_CHAIN )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );

        strPath = getNameFromDN( cert.getSubjectDN() );

        strLabel = "Export chain";
        strPath += "_full_chain.pem";

        strName = cert.getSubjectDN();
        strInfo = QString( "Num       : %1\n"
                          "Algorithm : %2\n")
                      .arg( data_num_ )
                      .arg( cert.getSignAlg() );
    }


    if( export_type_ == EXPORT_TYPE_PFX || export_type_ == EXPORT_TYPE_ENC_PRIKEY )
    {
        mEncGroup->setEnabled( true );
    }
    else
        mEncGroup->setEnabled( false );

    if( exportType() == EXPORT_TYPE_PFX || exportType() == EXPORT_TYPE_FULL_CHAIN || exportType() == EXPORT_TYPE_CHAIN )
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
