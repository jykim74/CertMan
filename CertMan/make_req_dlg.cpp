#include "make_req_dlg.h"
#include "ui_make_req_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "key_pair_rec.h"
#include "req_rec.h"
#include "db_mgr.h"
#include "js_gen.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_pki_eddsa.h"
#include "settings_mgr.h"
#include "commons.h"
#include "pin_dlg.h"

static QStringList sMechList = { kMechRSA, kMechEC, kMechDSA, kMechEdDSA };

MakeReqDlg::MakeReqDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mKeyNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(keyNameChanged(int)));
    connect( mGenKeyPairCheck, SIGNAL(clicked()), this, SLOT(checkGenKeyPair()));
    connect( mNewAlgorithmCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(newAlgChanged(int)));
    connect( mNewOptionCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(newOptionChanged(int)));

    initialize();
}

MakeReqDlg::~MakeReqDlg()
{

}

void MakeReqDlg::setKeyName( const QString strName )
{
    mKeyNameCombo->setCurrentText( strName );
}

void MakeReqDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    mHashCombo->addItems(kHashList);
    mHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

    key_list_.clear();
    dbMgr->getKeyPairList( 0, key_list_ );

    for( int i = 0; i < key_list_.size(); i++ )
    {
        KeyPairRec keyRec = key_list_.at(i);
        mKeyNameCombo->addItem( keyRec.getName() );
    }

    mNewExponentText->setText( "65537" );
    mNewOptionCombo->clear();
    mNewOptionCombo->addItems( kRSAOptionList );
    mNewOptionCombo->setCurrentText( "2048" );
    mNewAlgorithmCombo->clear();

    mNewAlgorithmCombo->addItems( sMechList );

    if( manApplet->settingsMgr()->PKCS11Use() )
    {
        mNewAlgorithmCombo->addItem( kMechPKCS11_RSA );
        mNewAlgorithmCombo->addItem( kMechPKCS11_EC );
        mNewAlgorithmCombo->addItem( kMechPKCS11_DSA );
    }

    if( manApplet->settingsMgr()->KMIPUse() )
    {
        mNewAlgorithmCombo->addItem( kMechKMIP_RSA );
        mNewAlgorithmCombo->addItem( kMechKMIP_EC );
    }

    if( key_list_.size() > 0 )
    {
        mKeyInfoTab->setCurrentIndex(0);
        mKeyInfoTab->setTabEnabled(1, false);
    }
    else
    {
        mGenKeyPairCheck->setChecked(true);
        checkGenKeyPair();
    }

    if( key_list_.size() > 0 ) keyNameChanged(0);
}

int MakeReqDlg::genKeyPair( KeyPairRec& keyPair )
{
    int ret = 0;
    BIN binPri = {0,0};
    BIN binPub = {0,0};
    char *pPriHex = NULL;
    char *pPubHex = NULL;


    QString strAlg = mNewAlgorithmCombo->currentText();
    QString strName = mNewKeyNameText->text();
    int nExponent = mNewExponentText->text().toInt();
    QString strParam = mNewOptionCombo->currentText();

    if( manApplet->isLicense() == false )
    {
        int nTotalCnt = manApplet->dbMgr()->getKeyPairCountAll();

        if( nTotalCnt >= JS_NO_LICENSE_KEYPAIR_LIMIT_COUNT )
        {
            manApplet->warningBox( tr( "You could not make key pair than max key count(%1) in no license")
                                   .arg( JS_NO_LICENSE_KEYPAIR_LIMIT_COUNT ), this );
            return -1;
        }
    }

    if( strAlg == kMechRSA )
    {
        int nKeySize = mNewOptionCombo->currentText().toInt();

        ret = JS_PKI_RSAGenKeyPair( nKeySize, nExponent, &binPub, &binPri );
    }
    else if( strAlg == kMechEC )
    {
        int nGroupID = JS_PKI_getNidFromSN( mNewOptionCombo->currentText().toStdString().c_str() );
        ret = JS_PKI_ECCGenKeyPair( nGroupID, &binPub, &binPri );
    }
    else if( strAlg == kMechDSA )
    {
        int nKeySize = mNewOptionCombo->currentText().toInt();

        ret = JS_PKI_DSA_GenKeyPair( nKeySize, &binPub, &binPri );
    }
    else if( strAlg == kMechEdDSA )
    {
        int nParam = 0;

        if( mNewOptionCombo->currentText() == "Ed25519" )
            nParam = JS_PKI_KEY_TYPE_ED25519;
        else if( mNewOptionCombo->currentText() == "Ed448" )
            nParam = JS_PKI_KEY_TYPE_ED448;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
    }
    else if( strAlg == kMechPKCS11_RSA || strAlg == kMechPKCS11_EC || strAlg == kMechPKCS11_DSA )
    {
        int nIndex = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        CK_SESSION_HANDLE hSession = getP11Session( (JP11_CTX *)manApplet->P11CTX(), nIndex, strPIN );

        if( hSession < 0 )
        {
            manApplet->elog( "fail to get P11Session" );
            goto end;
        }

        ret = genKeyPairWithP11(
                    (JP11_CTX *)manApplet->P11CTX(),
                    strName,
                    strAlg,
                    strParam,
                    nExponent,
                    &binPri,
                    &binPub );

        JS_PKCS11_Logout( (JP11_CTX *)manApplet->P11CTX() );
        JS_PKCS11_CloseSession( (JP11_CTX *)manApplet->P11CTX() );
    }
    else if( strAlg == kMechKMIP_RSA || strAlg == kMechKMIP_EC )
    {
        ret = genKeyPairWithKMIP(
                    manApplet->settingsMgr(),
                    strAlg,
                    strParam,
                    &binPri,
                    &binPub );
    }

    if( ret != 0 ) goto end;

    if( manApplet->isPasswd() )
    {
        QString strHex = manApplet->getEncPriHex( &binPri );
        keyPair.setPrivateKey( strHex );
    }
    else
    {
        JS_BIN_encodeHex( &binPri, &pPriHex );
        keyPair.setPrivateKey( pPriHex );
    }

    JS_BIN_encodeHex( &binPub, &pPubHex );

    keyPair.setAlg( strAlg );
    keyPair.setRegTime( time(NULL) );
    keyPair.setName( strName );
    keyPair.setParam( strParam );
    keyPair.setPublicKey( pPubHex );
    keyPair.setStatus(0);


    ret = manApplet->dbMgr()->addKeyPairRec( keyPair );
    if( ret == 0 )
    {
        int nSeq = manApplet->dbMgr()->getSeq( "TB_KEY_PAIR" );
        keyPair.setNum( nSeq );
        if( manApplet->isPRO() ) addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_KEY_PAIR, "" );
    }

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binPub );
    if( pPriHex ) JS_free( pPriHex );
    if( pPubHex ) JS_free( pPubHex );

    return ret;
}

void MakeReqDlg::accept()
{
    int nAlg = -1;
    int ret = 0;
    BIN binPri = {0,0};
    BIN binCSR = {0,0};
    BIN binPubKey = {0,0};
    char *pHexCSR = NULL;
    KeyPairRec keyRec;
    ReqRec reqRec;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    QString strName = mNameText->text();
    QString strChallenge = mChallengePassText->text();

    if( strName.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert name"), this );
        mNameText->setFocus();
        return;
    }

    if( manApplet->isLicense() == false )
    {
        int nTotalCnt = dbMgr->getReqCountAll();

        if( nTotalCnt >= JS_NO_LICENSE_CSR_LIMIT_COUNT )
        {
            manApplet->warningBox( tr( "You could not make csr than max csr count(%1) in no license")
                                   .arg( JS_NO_LICENSE_CSR_LIMIT_COUNT ), this );
            return;
        }
    }

    QString strDN = mDNText->text();

    if( strDN.isEmpty() )
    {
        manApplet->warningBox( tr("You have to insert DN"), this );
        mDNText->setFocus();
        return;
    }

    QString strAlg;
    QString strHash = mHashCombo->currentText();

    if( mGenKeyPairCheck->isChecked() )
    {
        ret = genKeyPair( keyRec );
        if( ret != 0 ) goto end;

        strAlg = mNewAlgorithmCombo->currentText();
    }
    else
    {
        int keyIdx = mKeyNameCombo->currentIndex();
        keyRec = key_list_.at( keyIdx );
        strAlg = mAlgorithmText->text();
    }

    if( strAlg == kMechPKCS11_RSA || strAlg == kMechPKCS11_EC || strAlg == kMechPKCS11_DSA )
    {
        JP11_CTX *pP11CTX = (JP11_CTX *)manApplet->P11CTX();
        int nSlotID = manApplet->settingsMgr()->slotIndex();
        QString strPIN = manApplet->settingsMgr()->PKCS11Pin();

        BIN binID = {0,0};

        CK_SESSION_HANDLE hSession = getP11Session( pP11CTX, nSlotID, strPIN );
        if( hSession < 0 )
        {
            goto end;
        }

        if( strAlg == kMechPKCS11_RSA )
            nAlg = JS_PKI_KEY_TYPE_RSA;
        else if( strAlg == kMechPKCS11_EC )
            nAlg = JS_PKI_KEY_TYPE_ECC;
        else if( strAlg == kMechPKCS11_DSA )
            nAlg = JS_PKI_KEY_TYPE_DSA;
        else
        {
            manApplet->warningBox( tr( "not support PKCS11 algorithm: %1").arg( strAlg ) );
            goto end;
        }

        JS_BIN_decodeHex( keyRec.getPrivateKey().toStdString().c_str(), &binID );
        JS_BIN_decodeHex( keyRec.getPublicKey().toStdString().c_str(), &binPubKey );

        manApplet->log( QString( "ID : %1").arg( getHexString(&binID)));

        ret = JS_PKI_makeCSRByP11( nAlg,
                                   strHash.toStdString().c_str(),
                                   strDN.toStdString().c_str(),
                                   strChallenge.length() > 0 ? strChallenge.toStdString().c_str() : NULL,
                                   &binID,
                                   &binPubKey,
                                   NULL,
                                   pP11CTX,
                                   &binCSR );

        JS_BIN_reset( &binID );

        JS_PKCS11_Logout( pP11CTX );
        JS_PKCS11_CloseSession( pP11CTX );
    }
    else if( strAlg == kMechKMIP_RSA || strAlg == kMechKMIP_EC )
    {
        if( manApplet->settingsMgr()->KMIPUse() == 0 )
            goto end;

        SSL_CTX *pCTX = NULL;
        SSL *pSSL = NULL;
        Authentication  *pAuth = NULL;
        BIN binID = {0,0};

        if( strAlg == kMechKMIP_RSA )
            nAlg = JS_PKI_KEY_TYPE_RSA;
        else
            nAlg = JS_PKI_KEY_TYPE_ECC;

        JS_BIN_decodeHex( keyRec.getPrivateKey().toStdString().c_str(), &binID );
        JS_BIN_decodeHex( keyRec.getPublicKey().toStdString().c_str(), &binPubKey );

        ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );

        if( ret == 0 )
        {
            ret = JS_PKI_makeCSRByKMIP( nAlg,
                                        strHash.toStdString().c_str(),
                                        strDN.toStdString().c_str(),
                                        strChallenge.length() > 0 ? strChallenge.toStdString().c_str() : NULL,
                                        &binID,
                                        &binPubKey,
                                        NULL,
                                        pSSL,
                                        pAuth,
                                        &binCSR );
        }

        if( pSSL ) JS_SSL_clear( pSSL );
        if( pCTX ) JS_SSL_finish( &pCTX );
        if( pAuth )
        {
            JS_KMS_resetAuthentication( pAuth );
            JS_free( pAuth );
        }
        JS_BIN_reset( &binID );
    }
    else
    {
        if( strAlg == kMechRSA )
        {
            nAlg = JS_PKI_KEY_TYPE_RSA;
        }
        else if( strAlg == kMechEC )
        {
            nAlg = JS_PKI_KEY_TYPE_ECC;
        }
        else if( strAlg == kMechDSA )
        {
            nAlg = JS_PKI_KEY_TYPE_DSA;
        }
        else if( strAlg == kMechEdDSA )
        {
            QString strOption = mOptionText->text();

            if( strOption.toLower() == "ed25519" )
                nAlg = JS_PKI_KEY_TYPE_ED25519;
            else
                nAlg = JS_PKI_KEY_TYPE_ED448;
        }

        if( manApplet->isPasswd() )
            manApplet->getDecPriBIN( keyRec.getPrivateKey(), &binPri );
        else
            JS_BIN_decodeHex( keyRec.getPrivateKey().toStdString().c_str(), &binPri );

        ret = JS_PKI_makeCSR( nAlg,
                              mHashCombo->currentText().toStdString().c_str(),
                              strDN.toStdString().c_str(),
                              strChallenge.length() > 0 ? strChallenge.toStdString().c_str() : NULL,
                              &binPri,
                              NULL,
                              &binCSR );
    }


    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to make request"), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCSR, &pHexCSR );

    reqRec.setName( strName );
    reqRec.setRegTime( time(NULL) );
    reqRec.setCSR( QString(pHexCSR) );
    reqRec.setDN( strDN );
    reqRec.setHash( mHashCombo->currentText() );
    reqRec.setKeyNum( keyRec.getNum() );
    reqRec.setStatus(0);

    dbMgr->addReqRec( reqRec );
    dbMgr->modKeyPairStatus( keyRec.getNum(), 1 );
    if( manApplet->isPRO() ) addAudit( dbMgr, JS_GEN_KIND_CERTMAN, JS_GEN_OP_GEN_CSR, strDN );

end :
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binPubKey );
    if( pHexCSR ) JS_free( pHexCSR );

    if( ret == 0 )
    {
        manApplet->mainWindow()->createRightRequestList();
        QDialog::accept();
    }
}

void MakeReqDlg::keyNameChanged(int index)
{
    KeyPairRec keyRec = key_list_.at(index);

    mAlgorithmText->setText( keyRec.getAlg() );
    mOptionText->setText( keyRec.getParam() );

    if( keyRec.getAlg() == "RSA" || keyRec.getAlg() == kMechPKCS11_RSA || keyRec.getAlg() == kMechKMIP_RSA || keyRec.getAlg() == kMechDSA )
    {
        mOptionLabel->setText( "Key Size" );
    }
    else
    {
        mOptionLabel->setText( "NamedCurve" );
    }

    if( mOptionText->text() == "SM2" )
        mHashCombo->setCurrentText( "SM3" );

    if( keyRec.getAlg() == kMechEdDSA )
        mHashCombo->setEnabled(false);
    else
        mHashCombo->setEnabled(true);

    QString strTitle = keyRec.getName();
    strTitle += "(REQ)";
    mNameText->setText( strTitle );

    QString strDN = QString( "CN=%1,%2").arg( keyRec.getName() ).arg( manApplet->settingsMgr()->baseDN() );
    mDNText->setText( strDN );
}

void MakeReqDlg::newAlgChanged(int index )
{
    QString strAlg = mNewAlgorithmCombo->currentText();
    mNewOptionCombo->clear();

    if( strAlg == "RSA" || strAlg == kMechPKCS11_RSA || strAlg == kMechKMIP_RSA )
    {
        mNewOptionCombo->addItems( kRSAOptionList );
        mNewOptionCombo->setCurrentText( "2048" );
        mNewExponentText->setEnabled(true);
        mNewExponentLabel->setEnabled(true);
        mNewOptionLabel->setText( "Key Length" );
        mHashCombo->setEnabled(true);
    }
    else if( strAlg == kMechDSA )
    {
        mNewOptionCombo->addItems( kDSAOptionList );
        mNewOptionCombo->setCurrentText( "2048" );
        mNewExponentText->setEnabled(false);
        mNewExponentLabel->setEnabled(false);
        mNewOptionLabel->setText( "Key Length" );
        mHashCombo->setEnabled(true);
    }
    else if( strAlg == kMechEC )
    {
       mNewOptionCombo->addItems( kECCOptionList );
       mNewOptionCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );
       mNewExponentText->setEnabled(false);
       mNewExponentLabel->setEnabled(false);
       mNewOptionLabel->setText( "Named Curve" );
       mHashCombo->setEnabled(true);
    }
    else if( strAlg == kMechEdDSA )
    {
        mNewOptionCombo->addItems( kEdDSAOptionList );
        mNewExponentText->setEnabled(false);
        mNewExponentLabel->setEnabled(false);
        mNewOptionLabel->setText( "Named Curve" );
        mHashCombo->setEnabled(false);
    }
}

void MakeReqDlg::newOptionChanged(int index )
{
    if( mNewOptionCombo->currentText() == "SM2" )
        mHashCombo->setCurrentText( "SM3" );
}

void MakeReqDlg::checkGenKeyPair()
{
    bool bVal = mGenKeyPairCheck->isChecked();

    if( bVal )
    {
        mKeyInfoTab->setCurrentIndex(1);
        mKeyInfoTab->setTabEnabled(1, true );
        mKeyInfoTab->setTabEnabled(0, false);
    }
    else
    {
        mKeyInfoTab->setCurrentIndex(0);
        mKeyInfoTab->setTabEnabled(0, true);
        mKeyInfoTab->setTabEnabled(1, false );
    }
}

void MakeReqDlg::initUI()
{

}


