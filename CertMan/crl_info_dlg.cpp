/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "crl_info_dlg.h"
#include "js_pki.h"
#include "js_pki_x509.h"
#include "js_pki_ext.h"
#include "js_util.h"
#include "commons.h"

QTableWidgetItem* CRLInfoDlg::getExtNameItem( const QString strSN )
{
    QTableWidgetItem* item = NULL;

    if( strSN == JS_PKI_ExtNameAIA )
        item = new QTableWidgetItem( tr( "authorityInfoAccess" ));
    else if( strSN == JS_PKI_ExtNameAKI )
        item = new QTableWidgetItem( tr( "authorityKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameBC )
        item = new QTableWidgetItem( tr( "basicConstraints" ) );
    else if( strSN == JS_PKI_ExtNameCRLDP )
        item = new QTableWidgetItem( tr( "crlDistributionPoints" ) );
    else if( strSN == JS_PKI_ExtNameEKU )
        item = new QTableWidgetItem( tr( "extendedKeyUsage" ) );
    else if( strSN == JS_PKI_ExtNameIAN )
        item = new QTableWidgetItem( tr( "issuerAltName" ) );
    else if( strSN == JS_PKI_ExtNameKeyUsage )
        item = new QTableWidgetItem( tr( "keyUsage" ) );
    else if( strSN == JS_PKI_ExtNameNC )
        item = new QTableWidgetItem( tr( "nameConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePolicy )
        item = new QTableWidgetItem( tr( "certificatePolicies" ) );
    else if( strSN == JS_PKI_ExtNamePC )
        item = new QTableWidgetItem( tr( "policyConstraints" ) );
    else if( strSN == JS_PKI_ExtNamePM )
        item = new QTableWidgetItem( tr( "policyMappings" ) );
    else if( strSN == JS_PKI_ExtNameSKI )
        item = new QTableWidgetItem( tr( "subjectKeyIdentifier" ) );
    else if( strSN == JS_PKI_ExtNameSAN )
        item = new QTableWidgetItem( tr( "subjectAltName" ) );
    else if( strSN == JS_PKI_ExtNameCRLNum )
        item = new QTableWidgetItem( tr( "crlNumber" ) );
    else if( strSN == JS_PKI_ExtNameIDP )
        item = new QTableWidgetItem( tr( "issuingDistributionPoint" ) );
    else if( strSN == JS_PKI_ExtNameCRLReason )
        item = new QTableWidgetItem( tr( "CRLReason" ) );
    else
        item = new QTableWidgetItem( strSN );


    return item;
}


CRLInfoDlg::CRLInfoDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    initUI();
    crl_num_ = -1;
    ext_info_list_ = NULL;
    revoke_info_list_ = NULL;

    memset( &crl_info_, 0x00, sizeof(crl_info_));
    tabWidget->setCurrentIndex(0);
    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCRLTab->layout()->setSpacing(5);
    mCRLTab->layout()->setMargin(5);
    mRevokeTab->layout()->setSpacing(5);
    mRevokeTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

CRLInfoDlg::~CRLInfoDlg()
{
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( revoke_info_list_ ) JS_PKI_resetRevokeInfoList( &revoke_info_list_ );
}

void CRLInfoDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void CRLInfoDlg::clickVerifyCRL()
{
    int ret = 0;

    BIN binCRL = {0,0};
    BIN binCA = {0,0};
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You need to open the database"), this );
        return;
    }

    CRLRec crlRec;
    CertRec caRec;

    manApplet->dbMgr()->getCRLRec( crl_num_, crlRec );
    if( crlRec.getIssuerNum() <= 0 )
    {
        manApplet->warningBox( tr( "There is no CA information" ), this );
        return;
    }

    manApplet->dbMgr()->getCertRec( crlRec.getIssuerNum(), caRec );

    JS_BIN_decodeHex( crlRec.getCRL().toStdString().c_str(), &binCRL );
    JS_BIN_decodeHex( caRec.getCert().toStdString().c_str(), &binCA );

    ret = JS_PKI_verifyCRL( &binCRL, &binCA );
    if( ret == 1 )
    {
        manApplet->messageBox( tr("CRL Verification is successfull"), this );
    }
    else
    {
        manApplet->warningBox( tr( "CRL Verification failed [%1]" ).arg(ret), this);
    }

end :
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binCA );
}

void CRLInfoDlg::setCRLNum(int crl_num)
{
    crl_num_ = crl_num;
}

void CRLInfoDlg::initialize()
{
    int ret = 0;
    int i = 0;

    BIN binCRL = {0,0};
    BIN binFinger = {0,0};

    char    sThisUpdate[64];
    char    sNextUpdate[64];

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    tabWidget->setCurrentIndex(0);

    JS_PKI_resetCRLInfo( &crl_info_ );

    if( crl_num_ < 0 )
    {
        manApplet->warningBox( tr("Select a CRL"), this );
        return;
    }

    clearTable();
    if( ext_info_list_ ) JS_PKI_resetExtensionInfoList( &ext_info_list_ );
    if( revoke_info_list_ ) JS_PKI_resetRevokeInfoList( &revoke_info_list_ );

    CRLRec crl;
    dbMgr->getCRLRec( crl_num_, crl );

    JS_BIN_decodeHex( crl.getCRL().toStdString().c_str(), &binCRL );

    ret = JS_PKI_getCRLInfo( &binCRL, &crl_info_, &ext_info_list_, &revoke_info_list_ );
    if( ret != 0 )
    {
        manApplet->warningBox( tr("fail to obtain CRL information"), this );
        JS_BIN_reset( &binCRL );
        close();
        return;
    }

    JS_PKI_genHash( "SHA1", &binCRL, &binFinger );

    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("Version")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("V%1").arg(crl_info_.nVersion+1)));
    i++;

    if( crl_info_.pIssuerName )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("IssuerName")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pIssuerName)));
        i++;
    }


    JS_UTIL_getDateTime( crl_info_.tThisUpdate, sThisUpdate );
    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("ThisUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sThisUpdate)));
    i++;

    JS_UTIL_getDateTime( crl_info_.tNextUpdate, sNextUpdate );
    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("NextUpdate")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(sNextUpdate)));
    i++;

    if( crl_info_.pSignAlgorithm )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("SignAlgorithm")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pSignAlgorithm)));
        i++;
    }

    if( crl_info_.pSignature )
    {
        mCRLListTable->insertRow(i);
        mCRLListTable->setRowHeight(i,10);
        mCRLListTable->setItem( i, 0, new QTableWidgetItem( tr("Signature")));
        mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(crl_info_.pSignature)));
        i++;
    }

    if( ext_info_list_ )
    {
        JExtensionInfoList *pCurList = ext_info_list_;

        while( pCurList )
        {
            QString strValue;
            QString strSN = pCurList->sExtensionInfo.pOID;
            bool bCrit = pCurList->sExtensionInfo.bCritical;
            getInfoValue( &pCurList->sExtensionInfo, strValue );

            QTableWidgetItem *item = new QTableWidgetItem( strValue );
            if( bCrit )
                item->setIcon(QIcon(":/images/critical.png"));
            else
                item->setIcon(QIcon(":/images/normal.png"));

            mCRLListTable->insertRow(i);
            mCRLListTable->setRowHeight(i,10);
            mCRLListTable->setItem(i,0, getExtNameItem(strSN));
            mCRLListTable->setItem(i,1, item );

            pCurList = pCurList->pNext;
            i++;
        }
    }

    mCRLListTable->insertRow(i);
    mCRLListTable->setRowHeight(i,10);
    mCRLListTable->setItem(i, 0, new QTableWidgetItem(tr("FingerPrint")));
    mCRLListTable->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(getHexString(&binFinger))));
    i++;

    if( revoke_info_list_ )
    {
        int k = 0;
        JRevokeInfoList *pCurRevList = revoke_info_list_;
        char sRevokeDate[64];

        while( pCurRevList )
        {
            JS_UTIL_getDateTime( pCurRevList->sRevokeInfo.uRevokeDate, sRevokeDate );

            mRevokeListTable->insertRow(k);
            mRevokeListTable->setRowHeight(k,10);
            mRevokeListTable->setItem( k, 0, new QTableWidgetItem(QString("%1").arg( pCurRevList->sRevokeInfo.pSerial)));
            mRevokeListTable->setItem( k, 1, new QTableWidgetItem(QString("%1").arg( sRevokeDate )));

            pCurRevList = pCurRevList->pNext;
            k++;
        }
    }

    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binFinger );
}

void CRLInfoDlg::initUI()
{
    QStringList sCRLLabels = { tr("Field"), tr("Value") };

    mCRLListTable->clear();
    mCRLListTable->horizontalHeader()->setStretchLastSection(true);
    mCRLListTable->setColumnCount(2);
    mCRLListTable->setHorizontalHeaderLabels( sCRLLabels );
    mCRLListTable->verticalHeader()->setVisible(false);
    mCRLListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mCRLListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mCRLListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mCRLListTable->setColumnWidth( 0, 140 );

    QStringList sRevokeLabels = { tr("Serial"), tr("RevokedDate") };
    mRevokeListTable->clear();
    mRevokeListTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeListTable->setColumnCount(2);
    mRevokeListTable->setHorizontalHeaderLabels( sRevokeLabels );
    mRevokeListTable->verticalHeader()->setVisible(false);
    mRevokeListTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeListTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mRevokeListTable->setColumnWidth( 0, 180 );

    mRevokeDetailTable->clear();
    mRevokeDetailTable->horizontalHeader()->setStretchLastSection(true);
    mRevokeDetailTable->setColumnCount(2);
    mRevokeDetailTable->setHorizontalHeaderLabels(sCRLLabels);
    mRevokeDetailTable->verticalHeader()->setVisible(false);
    mRevokeDetailTable->horizontalHeader()->setStyleSheet( kTableStyle );
    mRevokeDetailTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    mRevokeDetailTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    connect( mVerifyCRLBtn, SIGNAL(clicked()), this, SLOT(clickVerifyCRL()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mCRLListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickCRLField(QModelIndex)));
    connect( mRevokeListTable, SIGNAL(clicked(QModelIndex)), this, SLOT(clickRevokeField(QModelIndex)));
}

void CRLInfoDlg::clearTable()
{
    int rowCnt = mCRLListTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mCRLListTable->removeRow(0);

    rowCnt = mRevokeListTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeListTable->removeRow(0);

    rowCnt = mRevokeDetailTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeDetailTable->removeRow(0);
}

void CRLInfoDlg::clickCRLField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    QTableWidgetItem* item = mCRLListTable->item( row, 1 );
    if( item == NULL ) return;

    mCRLDetailText->setPlainText( item->text() );
}

void CRLInfoDlg::clickRevokeField(QModelIndex index)
{
    int row = index.row();
    int col = index.column();

    int rowCnt = mRevokeDetailTable->rowCount();

    for( int i=0; i < rowCnt; i++ )
        mRevokeDetailTable->removeRow(0);

    JRevokeInfoList *pRevInfoList = revoke_info_list_;

    for( int i = 0; i < row; i++ )
    {
        pRevInfoList = pRevInfoList->pNext;
    }

    char sRevokeDate[64];

    JS_UTIL_getDateTime( pRevInfoList->sRevokeInfo.uRevokeDate, sRevokeDate );

    mRevokeDetailTable->insertRow(0);
    mRevokeDetailTable->setRowHeight(0,10);
    mRevokeDetailTable->setItem( 0, 0, new QTableWidgetItem( QString("Serial" )));
    mRevokeDetailTable->setItem( 0, 1, new QTableWidgetItem( QString( pRevInfoList->sRevokeInfo.pSerial )));

    mRevokeDetailTable->insertRow(1);
    mRevokeDetailTable->setRowHeight(1,10);
    mRevokeDetailTable->setItem( 1, 0, new QTableWidgetItem( QString("RevokedDate" )));
    mRevokeDetailTable->setItem( 1, 1, new QTableWidgetItem( QString( "%1" ).arg( sRevokeDate )));

    if( pRevInfoList->sRevokeInfo.sExtReason.pOID )
    {
        QString strValue = pRevInfoList->sRevokeInfo.sExtReason.pValue;
        QString strSN = pRevInfoList->sRevokeInfo.sExtReason.pOID;
        bool bCrit = pRevInfoList->sRevokeInfo.sExtReason.bCritical;

        mRevokeDetailTable->insertRow(2);
        mRevokeDetailTable->setRowHeight(2,10);

        getInfoValue( &pRevInfoList->sRevokeInfo.sExtReason, strValue );

        QTableWidgetItem *item = new QTableWidgetItem( strValue );
        if( bCrit )
            item->setIcon(QIcon(":/images/critical.png"));
        else
            item->setIcon(QIcon(":/images/normal.png"));

        mRevokeDetailTable->setItem(2,0, new QTableWidgetItem(QString("%1").arg(strSN)));
        mRevokeDetailTable->setItem(2,1,item);
    }

}

const QString CRLInfoDlg::getCRL_URIFromExt( const QString strExtCRLDP )
{
    QString strURI;
    QString strCRLDP;

    strCRLDP = getExtValue( JS_PKI_ExtNameIDP, strExtCRLDP, false );

    QStringList infoList = strCRLDP.split( "#" );

    for( int i = 0; i < infoList.size(); i++ )
    {
        QString strPart = infoList.at(i);
        QStringList partList = strPart.split( "$" );
        if( partList.size() < 2 ) continue;

        if( partList.at(0) == "URI" )
        {
            strURI = partList.at(1);
            break;
        }
    }

    return strURI;
}

const QString CRLInfoDlg::getValueFromExtList( const QString strExtName, JExtensionInfoList *pExtList )
{
    QString strValue;

    JExtensionInfoList *pCurList = NULL;

    pCurList = pExtList;

    while( pCurList )
    {
        QString strSN;

        strSN = pCurList->sExtensionInfo.pOID;

        if( strSN == strExtName )
        {
            strValue = pCurList->sExtensionInfo.pValue;
            break;
        }

        pCurList = pCurList->pNext;
    }

    return strValue;
}
