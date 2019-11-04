#include "make_cert_dlg.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "req_rec.h"
#include "cert_rec.h"
#include "cert_policy_rec.h"
#include "key_pair_rec.h"
#include "db_mgr.h"

#include "js_pki.h"
#include "js_pki_x509.h"

QString getSignAlg( const QString strAlg, const QString strHash )
{
    QString strSignAlgorithm;

    strSignAlgorithm = strHash.toUpper();
    strSignAlgorithm += "WITH";

    if( strAlg == "EC" || strAlg == "ECC" )
        strSignAlgorithm += "ECDSA";
    else
        strSignAlgorithm += strAlg.toUpper();

    return strSignAlgorithm;
}

MakeCertDlg::MakeCertDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mReqNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(reqChanged(int)));
    connect( mIssuerNameCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(issuerChanged(int)));
    connect( mSelfSignCheck, SIGNAL(clicked()), this, SLOT(clickSelfSign()));

//    initialize();
}

MakeCertDlg::~MakeCertDlg()
{

}

void MakeCertDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void MakeCertDlg::initialize()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    req_list_.clear();

    dbMgr->getReqList( req_list_ );
    for( int i = 0; i < req_list_.size(); i++ )
    {
        ReqRec reqRec = req_list_.at(i);
        mReqNameCombo->addItem( reqRec.getName() );
    }

    ca_cert_list_.clear();

    dbMgr->getCACertList( ca_cert_list_ );
    for( int i=0; i < ca_cert_list_.size(); i++ )
    {
        CertRec certRec = ca_cert_list_.at(i);
        mIssuerNameCombo->addItem( certRec.getSubjectDN() );
    }

    cert_policy_list_.clear();

    dbMgr->getCertPolicyList( cert_policy_list_ );
    for( int i=0; i < cert_policy_list_.size(); i++ )
    {
        CertPolicyRec certPolicyRec = cert_policy_list_.at(i);
        mPolicyNameCombo->addItem( certPolicyRec.getName() );
    }
}

void MakeCertDlg::accept()
{
    int ret = 0;
    JSCertInfo sCertInfo;
    JSCertInfo sMadeCertInfo;
    BIN binCSR = {0,0};
    BIN binSignPri = {0,0};
    BIN binSignCert = {0,0};
    BIN binCert = {0,0};
    char *pHexCert = NULL;

    CertRec madeCertRec;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;
    bool bSelf = mSelfSignCheck->isChecked();

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));
    memset( &sMadeCertInfo, 0x00, sizeof(sMadeCertInfo));

    if( req_list_.size() <= 0 )
    {
        manApplet->warningBox( tr("There is no request"), this );
        return;
    }

    if( cert_policy_list_.size() <= 0 )
    {
        manApplet->warningBox( tr( "There is no certificate policy"), this );
        return;
    }

    if( !bSelf )
    {
        if( ca_cert_list_.size() <= 0 )
        {
            manApplet->warningBox(tr("There is no CA certificate"), this );
            return;
        }
    }

    int reqIdx =  mReqNameCombo->currentIndex();
    int policyIdx = mPolicyNameCombo->currentIndex();
    int issuerIdx = mIssuerNameCombo->currentIndex();

    int nIssueKeyNum = -1;
    int nKeyType = -1;
    int nIssuerNum = -1;

    CertPolicyRec policyRec = cert_policy_list_.at( policyIdx );
    ReqRec reqRec = req_list_.at( reqIdx );

    if( bSelf )
        nIssueKeyNum = reqRec.getKeyNum();
    else {
        CertRec issuerCert = ca_cert_list_.at( issuerIdx );
        nIssueKeyNum = issuerCert.getKeyNum();
        nIssuerNum = issuerCert.getNum();
        JS_BIN_decodeHex( issuerCert.getCert().toStdString().c_str(), &binSignCert );
    }

    KeyPairRec issueKeyPair;
    dbMgr->getKeyPairRec( nIssueKeyNum, issueKeyPair );

    /* need to work more */

    QString strSerial;
    int nSeq = dbMgr->getSeq( "TB_CERT" );

    strSerial = QString("%1").arg(nSeq);
    QString strSignAlg = getSignAlg( issueKeyPair.getAlg(), policyRec.getHash() );
    if( issueKeyPair.getAlg() == "RSA" )
        nKeyType = JS_PKI_KEY_TYPE_RSA;
    else if( issueKeyPair.getAlg() == "EC" )
        nKeyType = JS_PKI_KEY_TYPE_ECC;


    QString strDN;
    if( policyRec.getDNTemplate() == "#CSR" )
        strDN = reqRec.getDN();
    else
        strDN = policyRec.getDNTemplate();

    time_t now_t = time(NULL);
    long notBefore = -1;
    long notAfter = -1;

    if( policyRec.getNotBefore() <= 0 )
    {
        long uValidSecs = policyRec.getNotAfter() * 60 * 60 * 24;
        notBefore = 0;
        notAfter = uValidSecs;
    }
    else
    {
        notBefore = policyRec.getNotBefore() - now_t;
        notAfter = policyRec.getNotAfter() - now_t;
    }

    JS_BIN_decodeHex( reqRec.getCSR().toStdString().c_str(), &binCSR );
    JS_BIN_decodeHex( issueKeyPair.getPrivateKey().toStdString().c_str(), &binSignPri );

    JS_PKI_setCertInfo( &sCertInfo,
                        nKeyType,
                        policyRec.getVersion(),
                        strSerial.toStdString().c_str(),
                        strSignAlg.toStdString().c_str(),
                        NULL,
                        strDN.toStdString().c_str(),
                        notBefore,
                        notAfter,
                        NULL,
                        NULL );

    /* need to support extensions start */
    /* need to support extensions end */

    ret = JS_PKI_makeCertificate( bSelf, &sCertInfo, policyRec.getHash().toStdString().c_str(), &binCSR, &binSignPri, &binSignCert, &binCert );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to make certificate(%1)").arg(ret), this );
        goto end;

    }

    ret = JS_PKI_getCertInfo( &binCert, &sMadeCertInfo );
    if( ret != 0 )
    {
        manApplet->warningBox(tr("fail to get certificate information(%1)").arg(ret), this );
        goto end;
    }

    JS_BIN_encodeHex( &binCert, &pHexCert );

    madeCertRec.setSelf( bSelf );
    madeCertRec.setStatus(0);
    madeCertRec.setSignAlg( sMadeCertInfo.pSignAlgorithm );
    madeCertRec.setCert( pHexCert );
    madeCertRec.setSubjectDN( sMadeCertInfo.pSubjectName );
    madeCertRec.setKeyNum( reqRec.getKeyNum() );
    madeCertRec.setCA( false );
    madeCertRec.setIssuerNum( nIssuerNum );


    dbMgr->addCertRec( madeCertRec );
    dbMgr->modReqStatus( reqRec.getSeq(), 1 );

end :
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binSignPri );
    JS_BIN_reset(&binSignCert);
    JS_BIN_reset(&binCSR);
    JS_PKI_resetCertInfo( &sCertInfo );
    JS_PKI_resetCertInfo( &sMadeCertInfo );
    if( pHexCert ) JS_free( pHexCert );

    if( ret == 0 ) QDialog::accept();
}

void MakeCertDlg::reqChanged( int index )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    ReqRec reqRec = req_list_.at(index);

    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( reqRec.getKeyNum(), keyPair );

    mAlgorithmText->setText( keyPair.getAlg() );
    mOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::issuerChanged( int index )
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec certRec = ca_cert_list_.at(index);
    KeyPairRec keyPair;
    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );

    mIssuerAlgorithmText->setText( keyPair.getAlg() );
    mIssuerOptionText->setText( keyPair.getParam() );
}

void MakeCertDlg::clickSelfSign()
{
    bool bStatus = mSelfSignCheck->isChecked();

    mIssuerNameCombo->setEnabled( !bStatus );
    mIssuerAlgorithmText->setEnabled( !bStatus );
    mIssuerOptionText->setEnabled( !bStatus );
}
