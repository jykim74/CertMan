/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QTreeView>
#include "man_tree_model.h"
#include "QtWidgets/qheaderview.h"
#include "man_tree_item.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "commons.h"
#include "settings_mgr.h"
#include "db_mgr.h"

#include "js_define.h"
#include "js_pki.h"

ManTreeModel::ManTreeModel( QObject *parent )
    : QStandardItemModel (parent)
{
    tree_view_ = new ManTreeView;
    tree_view_->setModel(this);
}

ManTreeModel::~ManTreeModel()
{
    if( root_ca_ ) delete root_ca_;
    if( tree_view_ ) delete tree_view_;
}

void ManTreeModel::clickTreeMenu( int nType, int nNum )
{
    ManTreeItem *topItem = (ManTreeItem *)invisibleRootItem();
    if( topItem == NULL ) return;

    ManTreeItem* item = tree_view_->getItem( topItem, nType, nNum );
    if( item )
    {
        tree_view_->clicked( item->index() );
        tree_view_->setCurrentIndex( item->index() );
        tree_view_->setFocus();
    }
}

void ManTreeModel::clickRootTreeMenu( int nType, int nNum )
{
    if( root_ca_ == NULL ) return;

    ManTreeItem* item = tree_view_->getItem( root_ca_, nType, nNum );
    if( item )
    {
        tree_view_->expand( item->index() );
        tree_view_->clicked( item->index() );
        tree_view_->setCurrentIndex( item->index() );
        tree_view_->setFocus();
    }
}

void ManTreeModel::createTreeMenu()
{
    clear();
    tree_view_->header()->setVisible(false);

    ManTreeItem *pRootItem = (ManTreeItem *)invisibleRootItem();

    ManTreeItem *pTopItem = new ManTreeItem( QString( tr("CertMan") ) );
    pTopItem->setIcon(QIcon(":/images/man.png"));
    pRootItem->insertRow( 0, pTopItem );

    ManTreeItem *pKeyPairItem = new ManTreeItem( QString( tr("KeyPair")) );
    pKeyPairItem->setIcon(QIcon(":/images/key_reg.png"));
    pKeyPairItem->setType( CM_ITEM_TYPE_KEYPAIR );
    pTopItem->appendRow( pKeyPairItem );

    ManTreeItem *pCSRItem = new ManTreeItem( QString( tr("CSR")));
    pCSRItem->setIcon(QIcon(":/images/csr.png"));
    pCSRItem->setType( CM_ITEM_TYPE_REQUEST );
    pTopItem->appendRow( pCSRItem );

    if( manApplet->isPRO() )
    {
        ManTreeItem *pManItem = new ManTreeItem( QString(tr("Manage")));
        pManItem->setIcon(QIcon(":/images/manage.png"));
        pTopItem->appendRow( pManItem );

        ManTreeItem *pAdminItem = new ManTreeItem( QString(tr("Admin")) );
        pAdminItem->setIcon(QIcon(":/images/admin.png"));
        pAdminItem->setType( CM_ITEM_TYPE_ADMIN );
        pManItem->appendRow( pAdminItem );

        ManTreeItem *pConfigItem = new ManTreeItem( QString(tr("Config")));
        pConfigItem->setIcon(QIcon(":/images/config.png"));
        pConfigItem->setType( CM_ITEM_TYPE_CONFIG );
        pConfigItem->setDataNum( -1 );
        pManItem->appendRow( pConfigItem );

        ManTreeItem *pOCSPSrvItem = new ManTreeItem( QString( tr( "OCSP Server" )));
        pOCSPSrvItem->setIcon(QIcon(":/images/config.png"));
        pOCSPSrvItem->setType( CM_ITEM_TYPE_CONFIG );
        pOCSPSrvItem->setDataNum( JS_GEN_KIND_OCSP_SRV );
        pConfigItem->appendRow( pOCSPSrvItem );

        ManTreeItem *pTSPSrvItem = new ManTreeItem( QString( tr( "TSP Server" )));
        pTSPSrvItem->setIcon(QIcon(":/images/config.png"));
        pTSPSrvItem->setType( CM_ITEM_TYPE_CONFIG );
        pTSPSrvItem->setDataNum( JS_GEN_KIND_TSP_SRV );
        pConfigItem->appendRow( pTSPSrvItem );

        ManTreeItem *pCMPSrvItem = new ManTreeItem( QString( tr( "CMP Server" )));
        pCMPSrvItem->setIcon(QIcon(":/images/config.png"));
        pCMPSrvItem->setType( CM_ITEM_TYPE_CONFIG );
        pCMPSrvItem->setDataNum( JS_GEN_KIND_CMP_SRV );
        pConfigItem->appendRow( pCMPSrvItem );

        ManTreeItem *pRegSrvItem = new ManTreeItem( QString( tr( "Reg Server" )));
        pRegSrvItem->setIcon(QIcon(":/images/config.png"));
        pRegSrvItem->setType( CM_ITEM_TYPE_CONFIG );
        pRegSrvItem->setDataNum( JS_GEN_KIND_REG_SRV );
        pConfigItem->appendRow( pRegSrvItem );

        ManTreeItem *pCCSrvItem = new ManTreeItem( QString( tr( "CC Server" )));
        pCCSrvItem->setIcon(QIcon(":/images/config.png"));
        pCCSrvItem->setType( CM_ITEM_TYPE_CONFIG );
        pCCSrvItem->setDataNum( JS_GEN_KIND_CC_SRV );
        pConfigItem->appendRow( pCCSrvItem );

        ManTreeItem *pKMSSrvItem = new ManTreeItem( QString( tr( "KMS Server" )));
        pKMSSrvItem->setIcon(QIcon(":/images/config.png"));
        pKMSSrvItem->setType( CM_ITEM_TYPE_CONFIG );
        pKMSSrvItem->setDataNum( JS_GEN_KIND_KMS_SRV );
        pConfigItem->appendRow( pKMSSrvItem );

        ManTreeItem *pRegSignerItem = new ManTreeItem( QString(tr("REGSigner")) );
        pRegSignerItem->setIcon(QIcon(":/images/reg_signer.png"));
        pRegSignerItem->setType( CM_ITEM_TYPE_REG_SIGNER );
        pManItem->appendRow( pRegSignerItem );

        ManTreeItem *pOCSPSignerItem = new ManTreeItem( QString(tr("OCSPSigner")) );
        pOCSPSignerItem->setIcon(QIcon(":/images/ocsp_signer.png"));
        pOCSPSignerItem->setType( CM_ITEM_TYPE_OCSP_SIGNER );
        pManItem->appendRow( pOCSPSignerItem );

        tree_view_->expand( pManItem->index() );

        ManTreeItem *pUserItem = new ManTreeItem( QString(tr("User")) );
        pUserItem->setIcon(QIcon(":/images/user.png"));
        pUserItem->setType( CM_ITEM_TYPE_USER );
        pTopItem->appendRow( pUserItem );
    }


    ManTreeItem *pCertProfileItem = new ManTreeItem( QString(tr("CertProfile") ) );
    pCertProfileItem->setIcon(QIcon(":/images/cert_profile.png"));
    pCertProfileItem->setType( CM_ITEM_TYPE_CERT_PROFILE );
    pTopItem->appendRow( pCertProfileItem );

    ManTreeItem *pCRLProfileItem = new ManTreeItem( QString( tr("CRLProfile") ) );
    pCRLProfileItem->setIcon(QIcon(":/images/crl_profile.png"));
    pCRLProfileItem->setType( CM_ITEM_TYPE_CRL_PROFILE );
    pTopItem->appendRow( pCRLProfileItem );

    ManTreeItem *pRootCAItem = new ManTreeItem( QString(tr("RootCA")) );
    pRootCAItem->setIcon( QIcon(":/images/root_cert.png") );
    pRootCAItem->setType(CM_ITEM_TYPE_ROOTCA);
    pRootCAItem->setDataNum( kSelfNum );
    pTopItem->appendRow( pRootCAItem );
    expandItem( pRootCAItem );
    root_ca_ = pRootCAItem;

    ManTreeItem *pImportCertItem = new ManTreeItem( QString( tr("Import Cert") ) );
    pImportCertItem->setIcon(QIcon(":/images/im_cert.png"));
    pImportCertItem->setType( CM_ITEM_TYPE_IMPORT_CERT );
    pTopItem->appendRow( pImportCertItem );

    ManTreeItem *pImportCRLItem = new ManTreeItem( QString( tr("Import CRL") ) );
    pImportCRLItem->setIcon(QIcon(":/images/im_crl.png"));
    pImportCRLItem->setType( CM_ITEM_TYPE_IMPORT_CRL );
    pTopItem->appendRow( pImportCRLItem );

    if( manApplet->isPRO() )
    {
        ManTreeItem *pServiceItem = new ManTreeItem( QString( tr("Service") ));
        pServiceItem->setIcon(QIcon(":/images/group.png"));
        pTopItem->appendRow( pServiceItem );

        ManTreeItem *pKMSItem = new ManTreeItem( QString( tr("KMS") ));
        pKMSItem->setIcon(QIcon(":/images/kms.png"));
        pKMSItem->setType( CM_ITEM_TYPE_KMS );
        pServiceItem->appendRow( pKMSItem );

        ManTreeItem *pTSPItem = new ManTreeItem( QString( tr("TSP") ));
        pTSPItem->setIcon(QIcon(":/images/timestamp.png"));
        pTSPItem->setType( CM_ITEM_TYPE_TSP );
        pServiceItem->appendRow( pTSPItem );

        tree_view_->expand( pServiceItem->index() );

#ifdef _ENABLE_CHARTS
        ManTreeItem *pStatisticsItem = new ManTreeItem( QString( tr("Statistics") ));
        pStatisticsItem->setIcon(QIcon(":/images/statistics.png"));
        pStatisticsItem->setType( CM_ITEM_TYPE_STATISTICS );
        pTopItem->appendRow( pStatisticsItem );
#endif

        ManTreeItem *pAuditItem = new ManTreeItem( QString( tr("Audit")) );
        pAuditItem->setIcon( QIcon(":/images/audit.png"));
        pAuditItem->setType( CM_ITEM_TYPE_AUDIT );
        pTopItem->appendRow( pAuditItem );

    }


    QModelIndex ri = index(0,0);
    tree_view_->expand(ri);

    //    expandItem( pRootCAItem );
}

void ManTreeModel::expandItem( ManTreeItem *item )
{
    int nIssuerNum = item->getDataNum();
    time_t now_t = time(NULL);

    QList<CertRec> certList;
    manApplet->dbMgr()->getCACertList( nIssuerNum, certList );

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec certRec = certList.at(i);

        ManTreeItem *pCAItem = new ManTreeItem( certRec.getSubjectDN() );
        pCAItem->setType( CM_ITEM_TYPE_CA );
        pCAItem->setDataNum( certRec.getNum() );

        if( now_t > certRec.getNotAfter() )
        {
            pCAItem->setIcon( QIcon(":/images/ca_expired.png" ));
        }
        else
        {
            if( certRec.getStatus() == JS_CERT_STATUS_REVOKE )
                pCAItem->setIcon( QIcon(":/images/ca_revoked.png") );
            else
                pCAItem->setIcon( QIcon(":/images/ca.png"));
        }

        item->appendRow( pCAItem );

        ManTreeItem *pCertItem = new ManTreeItem( QString(tr("Certificate")));
        pCertItem->setType( CM_ITEM_TYPE_CERT );
        pCertItem->setDataNum( certRec.getNum() );
        pCertItem->setIcon(QIcon(":/images/cert.png"));
        pCAItem->appendRow( pCertItem );

        ManTreeItem *pCRLItem = new ManTreeItem( QString(tr("CRL")) );
        pCRLItem->setType( CM_ITEM_TYPE_CRL );
        pCRLItem->setDataNum( certRec.getNum() );
        pCRLItem->setIcon(QIcon(":/images/crl.png"));
        pCAItem->appendRow( pCRLItem );

        ManTreeItem *pRevokeItem = new ManTreeItem( QString(tr("Revoke")));
        pRevokeItem->setType( CM_ITEM_TYPE_REVOKE );
        pRevokeItem->setDataNum( certRec.getNum() );
        pRevokeItem->setIcon(QIcon(":/images/revoke.png"));
        pCAItem->appendRow( pRevokeItem );

        int nCACount = manApplet->dbMgr()->getCACount( certRec.getNum() );
        if( nCACount > 0 )
        {
            ManTreeItem *pSubCAItem = new ManTreeItem( QString(tr("CA[%1]").arg( nCACount )));
            pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
            pSubCAItem->setIcon(QIcon(":/images/ca.png"));
            pSubCAItem->setDataNum( certRec.getNum() );
            pCAItem->appendRow( pSubCAItem );

            expandItem( pSubCAItem );
        }

        //        left_tree_->expand( pCAItem->index() );
    }

    tree_view_->expand( item->index() );
}

ManTreeItem* ManTreeModel::currentItem()
{
    ManTreeItem *item = NULL;
    QModelIndex index = tree_view_->currentIndex();

    item = (ManTreeItem *)itemFromIndex( index );

    return item;
}

void ManTreeModel::refreshRootCA()
{
    int rows = root_ca_->rowCount();
    root_ca_->removeRows( 0, rows );
    expandItem( root_ca_ );
}


void ManTreeModel::addRootCA( CertRec& certRec )
{
    if( root_ca_ == NULL ) return;

    ManTreeItem *pCAItem = new ManTreeItem( certRec.getSubjectDN() );
    pCAItem->setType( CM_ITEM_TYPE_CA );
    pCAItem->setDataNum( certRec.getNum() );
    pCAItem->setIcon( QIcon(":/images/ca.png"));
    root_ca_->appendRow( pCAItem );

    ManTreeItem *pCertItem = new ManTreeItem( QString(tr("Certificate")));
    pCertItem->setType( CM_ITEM_TYPE_CERT );
    pCertItem->setDataNum( certRec.getNum() );
    pCertItem->setIcon(QIcon(":/images/cert.png"));
    pCAItem->appendRow( pCertItem );

    ManTreeItem *pCRLItem = new ManTreeItem( QString(tr("CRL")) );
    pCRLItem->setType( CM_ITEM_TYPE_CRL );
    pCRLItem->setDataNum( certRec.getNum() );
    pCRLItem->setIcon(QIcon(":/images/crl.png"));
    pCAItem->appendRow( pCRLItem );

    ManTreeItem *pRevokeItem = new ManTreeItem( QString(tr("Revoke")));
    pRevokeItem->setType( CM_ITEM_TYPE_REVOKE );
    pRevokeItem->setDataNum( certRec.getNum() );
    pRevokeItem->setIcon(QIcon(":/images/revoke.png"));
    pCAItem->appendRow( pRevokeItem );

    ManTreeItem *pSubCAItem = new ManTreeItem( QString(tr("CA")));
    pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
    pSubCAItem->setIcon(QIcon(":/images/ca.png"));
    pSubCAItem->setDataNum( certRec.getNum() );
    pCAItem->appendRow( pSubCAItem );

    tree_view_->expand( root_ca_->index() );
}
