/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mainwindow.h"
#include "man_applet.h"
#include "pub_ldap_dlg.h"
#include "db_mgr.h"
#include "js_pki.h"
#include "js_ldap.h"
#include "js_pki_tools.h"
#include "settings_mgr.h"

static QStringList sTypeList = { "Certificate", "CRL" };

static QStringList sCertAttributeList = {
    "caCertificate", "signCertificate", "userCertificate"
};


static QStringList sCRLAttributeList = {
    "certificateRevocationList", "authorityRevocationList"
};

PubLDAPDlg::PubLDAPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();

    data_type_ = -1;
    data_num_ = -1;
}

PubLDAPDlg::~PubLDAPDlg()
{

}

void PubLDAPDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void PubLDAPDlg::accept()
{
    int ret = 0;
    int nType = -1;
    DBMgr* dbMgr = manApplet->dbMgr();

    BIN binData = {0,0};
    LDAP *pLD = NULL;

    if( dbMgr == NULL ) return;

    if( data_type_ == RightType::TYPE_CERTIFICATE )
    {
        CertRec cert;
        dbMgr->getCertRec( data_num_, cert );
        JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binData );
    }
    else if( data_type_ == RightType::TYPE_CRL )
    {
        CRLRec crl;
        dbMgr->getCRLRec( data_num_, crl );
        JS_BIN_decodeHex( crl.getCRL().toStdString().c_str(), &binData );
    }
    else
    {
        return;
    }

    nType = JS_LDAP_getType( mAttributeCombo->currentText().toStdString().c_str() );
    pLD = JS_LDAP_init( mLDAPHostText->text().toStdString().c_str(), mLDAPPortText->text().toInt());

    ret = JS_LDAP_bind( pLD, mBindDNText->text().toStdString().c_str(), mPasswordText->text().toStdString().c_str() );
    ret = JS_LDAP_publishData( pLD, mPublishDNText->text().toUtf8().toStdString().c_str(), nType, &binData );

    JS_BIN_reset( &binData );
    if( pLD ) JS_LDAP_close( pLD );
    if( ret == 0 ) QDialog::accept();
}

void PubLDAPDlg::initUI()
{
    mTypeCombo->addItems(sTypeList);
    mAttributeCombo->addItems(sCertAttributeList);

    QString strHost = manApplet->settingsMgr()->LDAPHost();
    QString strPort = QString("%1").arg( manApplet->settingsMgr()->LDAPPort() );


    mLDAPHostText->setText( strHost );
    mLDAPPortText->setText( strPort );
    mBindDNText->setText( "cn=Manager,c=kr" );
//    mPasswordText->setText( "secret" );

    connect( mTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(dataTypeChanged(int)));
}

void PubLDAPDlg::initialize()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( data_type_ == RightType::TYPE_CERTIFICATE )
    {
        CertRec cert;
        char *pPureDN = NULL;
        dbMgr->getCertRec( data_num_, cert );

        QString strInfo = QString( "DN: %1\nSignAlgorithm: %2\n")
                .arg( cert.getSubjectDN() )
                .arg( cert.getSignAlg() );


        mInfoText->setText( strInfo );

        JS_PKI_getPureDN( cert.getSubjectDN().toStdString().c_str(), &pPureDN );
        mPublishDNText->setText( pPureDN );
        if( pPureDN ) JS_free( pPureDN );
    }
    else if( data_type_ == RightType::TYPE_CRL )
    {
        CRLRec crl;
        dbMgr->getCRLRec( data_num_, crl );

        QString strInfo = QString( "Num: %1\nSignAlgorithm: %2")
                .arg( crl.getNum() )
                .arg( crl.getSignAlg() );

        mInfoText->setText( strInfo );
    }
    else
    {
        manApplet->warningBox(tr("Invalid data type"), this );
    }
}

void PubLDAPDlg::setDataType( int data_type )
{
    data_type_ = data_type;
}
void PubLDAPDlg::setDataNum( int data_num )
{
    data_num_ = data_num;
}

void PubLDAPDlg::dataTypeChanged(int index)
{
    mAttributeCombo->clear();

    if( index == 0 )
        mAttributeCombo->addItems( sCertAttributeList );
    else {
        mAttributeCombo->addItems( sCRLAttributeList );
    }
}
