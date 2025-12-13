/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "js_gen.h"
#include "js_define.h"

#include "revoke_cert_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "revoke_rec.h"
#include "cert_rec.h"
#include "commons.h"
#include "man_tree_view.h"


RevokeCertDlg::RevokeCertDlg(QWidget *parent) :
    QDialog(parent)
{
    cert_num_ = -1;
    setupUi(this);

    initUI();
//    initialize();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

RevokeCertDlg::~RevokeCertDlg()
{

}

void RevokeCertDlg::setCertNum(int cert_num)
{
    cert_num_ = cert_num;
    initialize();
}


void RevokeCertDlg::initialize()
{
    int ret = -1;
    if( cert_num_ < 0 ) return;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec cert;
    ret = dbMgr->getCertRec( cert_num_, cert );
    if( ret != 0 ) return;

    mSubjectDNText->setText( cert.getSubjectDN() );
    mSerialText->setText( QString("%1").arg(cert.getNum()));

    QDateTime dateTime = QDateTime::currentDateTime();
    mRevokeDateTime->setDateTime( dateTime );
}

void RevokeCertDlg::accept()
{
    int ret = -1;

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    CertRec cert;
    ret = dbMgr->getCertRec( cert_num_, cert );
    if( ret != 0 ) return;

    int nReason = mReasonCombo->currentIndex();

    RevokeRec revoke;
    revoke.setCertNum( cert_num_ );
    revoke.setIssuerNum( cert.getIssuerNum() );
    revoke.setSerial( QString("%1").arg(cert.getNum()));
    revoke.setReason( nReason );
    revoke.setRevokeDate( mRevokeDateTime->dateTime().toSecsSinceEpoch() );
    revoke.setCRLDP( cert.getCRLDP() );

    dbMgr->addRevokeRec( revoke );
    dbMgr->modCertStatus( cert_num_, JS_CERT_STATUS_REVOKE );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_REVOKE_CERT, "" );

//    manApplet->mainWindow()->createRightRevokeList( cert.getIssuerNum() );
    manApplet->clickRootTreeMenu( CM_ITEM_TYPE_REVOKE, cert.getIssuerNum() );
    QDialog::accept();
}

void RevokeCertDlg::initUI()
{
    mReasonCombo->addItems( kRevokeReasonList );
}
