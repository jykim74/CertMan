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
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

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

    int reqIdx =  mReqNameCombo->currentIndex();
    int policyIdx = mPolicyNameCombo->currentIndex();
    int issuerIdx = mIssuerNameCombo->currentIndex();

    int nIssueKeyNum = -1;

    CertPolicyRec policRec = cert_policy_list_.at( policyIdx );
    CertRec issuerCert = ca_cert_list_.at( issuerIdx );
    ReqRec reqRec = req_list_.at( reqIdx );

    if( mSelfSignCheck->isChecked() )
        nIssueKeyNum = reqRec.getKeyNum();
    else {
        nIssueKeyNum = issuerCert.getKeyNum();
    }

    KeyPairRec issueKeyPair;
    dbMgr->getKeyPairRec( nIssueKeyNum, issueKeyPair );

    /* need to work more */


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
