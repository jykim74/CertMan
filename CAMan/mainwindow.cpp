#include <QFileDialog>
#include <QtWidgets>

#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "man_tree_item.h"
#include "man_tree_model.h"
#include "man_tree_view.h"

#include "about_dlg.h"
#include "export_dlg.h"
#include "get_ldap_dlg.h"
#include "import_dlg.h"
#include "make_cert_dlg.h"
#include "make_cert_policy_dlg.h"
#include "make_crl_dlg.h"
#include "make_crl_policy_dlg.h"
#include "make_req_dlg.h"
#include "new_key_dlg.h"
#include "pub_ldap_dlg.h"
#include "revoke_cert_dlg.h"
#include "settings_dlg.h"
#include "settings_mgr.h"

#include "man_applet.h"
#include "db_mgr.h"
#include "cert_rec.h"
#include "key_pair_rec.h"
#include "req_rec.h"
#include "cert_policy_rec.h"
#include "crl_policy_rec.h"
#include "crl_rec.h"
#include "policy_ext_rec.h"
#include "revoke_rec.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    db_mgr_ = new DBMgr;

    initialize();

    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);
    setAcceptDrops(true);

    right_type_ = -1;
}

MainWindow::~MainWindow()
{
    delete hsplitter_;
    delete vsplitter_;
    delete left_tree_;
    delete left_model_;
    delete right_text_;
    delete right_table_;
}


void MainWindow::initialize()
{
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);
    left_tree_ = new ManTreeView(this);
    right_text_ = new QTextEdit();
    right_table_ = new QTableWidget;
    left_model_ = new ManTreeModel(this);

    left_tree_->setModel(left_model_);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget(vsplitter_);
    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget(right_text_);

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList <int> sizes;
    sizes << 500 << 1200;
    resize(1024,768);

    hsplitter_->setSizes(sizes);
    setCentralWidget(hsplitter_);

    connect( left_tree_, SIGNAL(clicked(QModelIndex)), this, SLOT(menuClick(QModelIndex)));
    connect( right_table_, SIGNAL(clicked(QModelIndex)), this, SLOT(tableClick(QModelIndex)));

    right_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect( right_table_, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showRightMenu(QPoint)));
}


void MainWindow::createActions()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    QToolBar *fileToolBar = addToolBar(tr("File"));

    const QIcon newIcon = QIcon::fromTheme("document-new", QIcon(":/images/new.png"));
    QAction *newAct = new QAction( newIcon, tr("&New"), this);
    newAct->setShortcut( QKeySequence::New);
    newAct->setStatusTip(tr("Create a new file"));
    connect( newAct, &QAction::triggered, this, &MainWindow::newFile);
    fileMenu->addAction(newAct);
    fileToolBar->addAction(newAct);

    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    QAction *openAct = new QAction( openIcon, tr("&Open..."), this );
    openAct->setShortcut(QKeySequence::Open);
    openAct->setStatusTip(tr("Open an existing ca db file"));
    connect( openAct, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(openAct);
    fileToolBar->addAction(openAct);

    fileMenu->addSeparator();

    QAction *quitAct = new QAction(tr("&Quit"), this );
    quitAct->setStatusTip( tr("Quit CAManager") );
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction( quitAct );

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    QToolBar *toolsToolBar = addToolBar(tr("Tools"));

    QAction *newKeyAct = toolsMenu->addAction(tr("&NewKey"), this, &MainWindow::newKey);
    newKeyAct->setStatusTip(tr( "Generate new key pair"));

    QAction *makeReqAct = toolsMenu->addAction(tr("&MakeRequest"), this, &MainWindow::makeRequest);
    makeReqAct->setStatusTip(tr( "Make Request"));

    QAction *makeCertPolicyAct = toolsMenu->addAction(tr("&MakeCertPolicy"), this, &MainWindow::makeCertPolicy);
    makeCertPolicyAct->setStatusTip(tr( "Make certificate policy"));

    QAction *makeCRLPolicyAct = toolsMenu->addAction(tr("&MakeCRLPolicy"), this, &MainWindow::makeCRLPolicy);
    makeCRLPolicyAct->setStatusTip(tr( "Make CRL Policy"));

    QAction *makeCertAct = toolsMenu->addAction(tr("&MakeCertificate"), this, &MainWindow::makeCertificate);
    makeCertAct->setStatusTip(tr( "Make certificate"));

    QAction *makeCRLAct = toolsMenu->addAction(tr("&MakeCRL"), this, &MainWindow::makeCRL );
    makeCRLAct->setStatusTip(tr( "Make CRL"));

    QAction *revokeCertAct = toolsMenu->addAction(tr("&RevokeCert"), this, &MainWindow::revokeCertificate);
    revokeCertAct->setStatusTip(tr( "Revoke certificate"));

    QMenu *importMenu = menuBar()->addMenu(tr("&Import"));
    QToolBar *importToolBar = addToolBar(tr("Import"));

    QAction* importPriKeyAct = importMenu->addAction(tr("&ImportPrivateKey"), this, &MainWindow::importPrivateKey);
    importPriKeyAct->setStatusTip(tr("Import private key"));

    QAction* importEncPriKeyAct = importMenu->addAction(tr("&ImportEncryptedPrivateKey"), this, &MainWindow::importEncPrivateKey);
    importEncPriKeyAct->setStatusTip(tr("Import encrypted private key"));

    QAction* importReqAct = importMenu->addAction(tr("&ImportRequest"), this, &MainWindow::importRequest);
    importReqAct->setStatusTip(tr("Import Request"));

    QAction* importCertAct = importMenu->addAction(tr("&ImportCertificate"), this, &MainWindow::importCertificate);
    importCertAct->setStatusTip(tr("Import certificate"));

    QAction* importCRLAct = importMenu->addAction(tr("&ImportCRL"), this, &MainWindow::importCRL);
    importCRLAct->setStatusTip(tr("Import CRL"));

    QAction* importPFXAct = importMenu->addAction(tr("&ImportPFX"), this, &MainWindow::importPFX);
    importPFXAct->setStatusTip(tr("Import PFX"));

    QMenu *exportMenu = menuBar()->addMenu(tr("&Export"));
    QToolBar *exprotToolBar = addToolBar(tr("Export"));

    QAction* exportPriKeyAct = exportMenu->addAction(tr("&ExportPrivateKey"), this, &MainWindow::exportPrivateKey);
    exportPriKeyAct->setStatusTip(tr("Export private key"));

    QAction* exportEncPriKeyAct = exportMenu->addAction(tr("&ExportEncryptedPrivateKey"), this, &MainWindow::exportEncPrivateKey);
    exportEncPriKeyAct->setStatusTip(tr("Export encrypted private key"));

    QAction* exportReqAct = exportMenu->addAction(tr("&ExportRequest"), this, &MainWindow::exportRequest);
    exportReqAct->setStatusTip(tr("Export Request"));

    QAction* exportCertAct = exportMenu->addAction(tr("&ExportCertificate"), this, &MainWindow::exportCertificate);
    exportCertAct->setStatusTip(tr("Export certificate"));

    QAction* exportCRLAct = exportMenu->addAction(tr("&ExportCRL"), this, &MainWindow::exportCRL);
    exportCRLAct->setStatusTip(tr("Export CRL"));

    QAction* exportPFXAct = exportMenu->addAction(tr("&ExportPFX"), this, &MainWindow::exportPFX);
    exportPFXAct->setStatusTip(tr("Export PFX"));

    QMenu *ldapMenu = menuBar()->addMenu(tr("&LDAP"));
    QToolBar *ldapToolBar = addToolBar(tr("LDAP"));

    QAction* pubLDAPAct = ldapMenu->addAction(tr("PublishLDAP"), this, &MainWindow::publishLDAP);
    pubLDAPAct->setStatusTip(tr("Publish LDAP"));

    QAction* getLDAPAct = ldapMenu->addAction(tr("GetLDAP"), this, &MainWindow::getLDAP);
    getLDAPAct->setStatusTip(tr("Get LDAP"));

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

    QAction *aboutAct = helpMenu->addAction(tr("About"), this, &MainWindow::about );
    aboutAct->setStatusTip(tr("About HsmMan"));

    QAction *settingsAct = helpMenu->addAction(tr("Settings"), this, &MainWindow::settings );
    settingsAct->setStatusTip(tr("Settings HsmMan"));
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createTableMenu()
{

}

void MainWindow::removeAllRight()
{
    right_text_->setText("");

    int rowCnt = right_table_->rowCount();

    for( int i=0; i < rowCnt; i++ )
        right_table_->removeRow(0);
}

void MainWindow::showRightMenu(QPoint point)
{
    QTableWidgetItem* item = right_table_->itemAt(point);
    if( item == NULL ) return;

    QMenu menu(this);

    if( right_type_ == RightType::TYPE_CERTIFICATE)
    {
        menu.addAction( tr("Export Certificate"), this, &MainWindow::exportCertificate );
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        menu.addAction( tr("Export CRL"), this, &MainWindow::exportCRL );
    }
    else if( right_type_ == RightType::TYPE_KEYPAIR )
    {
        menu.addAction(tr("Export PrivateKey"), this, &MainWindow::exportPrivateKey );
        menu.addAction(tr("Export EncryptedPrivate"), this, &MainWindow::exportEncPrivateKey );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        menu.addAction(tr("Export Request"), this, &MainWindow::exportRequest);
    }
    else if( right_type_ == RightType::TYPE_CERT_POLICY )
    {
        menu.addAction(tr("Delete CertPolicy"), this, &MainWindow::deleteCertPolicy );
    }
    else if( right_type_ == RightType::TYPE_CRL_POLICY )
    {
        menu.addAction(tr("Delete CRLPolicy"), this, &MainWindow::deleteCRLPolicy );
    }

    menu.exec(QCursor::pos());
}

void MainWindow::createTreeMenu()
{
    ManTreeItem *pRootItem = (ManTreeItem *)left_model_->invisibleRootItem();
    ManTreeItem *pTopItem = new ManTreeItem( QString( "CAManager" ) );
    pRootItem->insertRow( 0, pTopItem );

    ManTreeItem *pKeyPairItem = new ManTreeItem( QString("KeyPair") );
    pKeyPairItem->setType( CM_ITEM_TYPE_KEYPAIR );
    pTopItem->appendRow( pKeyPairItem );

    ManTreeItem *pCSRItem = new ManTreeItem( QString("Request"));
    pCSRItem->setType( CM_ITEM_TYPE_REQUEST );
    pTopItem->appendRow( pCSRItem );

    ManTreeItem *pCertPolicyItem = new ManTreeItem( QString("CertPolicy" ) );
    pCertPolicyItem->setType( CM_ITEM_TYPE_CERT_POLICY );
    pTopItem->appendRow( pCertPolicyItem );

    ManTreeItem *pCRLPolicyItem = new ManTreeItem( QString("CRLPolicy" ) );
    pCRLPolicyItem->setType( CM_ITEM_TYPE_CRL_POLICY );
    pTopItem->appendRow( pCRLPolicyItem );

    ManTreeItem *pRootCAItem = new ManTreeItem( QString("RootCA") );
    pRootCAItem->setType(CM_ITEM_TYPE_ROOTCA);
    pTopItem->appendRow( pRootCAItem );

    int nIssuerNum = -1;
    QList<CertRec> certList;
    db_mgr_->getCertList( nIssuerNum, certList );
    qDebug() << "RootCA count : " << certList.size();

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec certRec = certList.at(i);
        ManTreeItem *pCAItem = new ManTreeItem( certRec.getSubjectDN() );
        pCAItem->setType( CM_ITEM_TYPE_CA );
        pRootCAItem->appendRow( pCAItem );

        ManTreeItem *pCertItem = new ManTreeItem( QString("Certificate"));
        pCAItem->appendRow( pCertItem );

        ManTreeItem *pCRLItem = new ManTreeItem( QString("CRL") );
        pCAItem->appendRow( pCRLItem );

        ManTreeItem *pRevokeItem = new ManTreeItem( QString("Revoke"));
        pCAItem->appendRow( pRevokeItem );

        ManTreeItem *PSubCAItem = new ManTreeItem( QString("CA"));
        pCAItem->appendRow( PSubCAItem );
    }

    ManTreeItem *pImportCertItem = new ManTreeItem( QString( "ImportCert" ) );
    pImportCertItem->setType( CM_ITEM_TYPE_IMPORT_CERT );
    pTopItem->appendRow( pImportCertItem );

    ManTreeItem *pImportCRLItem = new ManTreeItem( QString( "ImportCRL" ) );
    pImportCRLItem->setType( CM_ITEM_TYPE_IMPORT_CRL );
    pTopItem->appendRow( pImportCRLItem );
}

void MainWindow::newFile()
{

}

void MainWindow::open()
{
    bool bSavePath = manApplet->settingsMgr()->saveDBPath();
    QString strPath = QDir::currentPath();

    if( bSavePath )
    {
        QSettings settings;
        settings.beginGroup("mainwindow");
        strPath = settings.value( "dbPath", "" ).toString();
        settings.endGroup();
    }


    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Open CAMan db file"),
                                                     strPath,
                                                     tr("DB Files (*.db);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    db_mgr_->close();
    int ret = db_mgr_->open(fileName);

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database"), this );
        return;
    }

    if( bSavePath )
    {
        QFileInfo fileInfo( fileName );
        QString strDir = fileInfo.dir().path();

        QSettings settings;
        settings.beginGroup("mainwindow");
        settings.setValue( "dbPath", strDir );
        settings.endGroup();
    }
    createTreeMenu();
}

void MainWindow::quit()
{
    QCoreApplication::exit();
}


void MainWindow::newKey()
{
    manApplet->newKeyDlg()->show();
    manApplet->newKeyDlg()->raise();
    manApplet->newKeyDlg()->activateWindow();
}

void MainWindow::makeRequest()
{
    manApplet->makeReqDlg()->show();
    manApplet->makeReqDlg()->raise();
    manApplet->makeReqDlg()->activateWindow();
}

void MainWindow::makeCertPolicy()
{
    manApplet->makeCertPolicyDlg()->show();
    manApplet->makeCertPolicyDlg()->raise();
    manApplet->makeCertPolicyDlg()->activateWindow();
}

void MainWindow::makeCRLPolicy()
{
    manApplet->makeCRLPolicyDlg()->show();
    manApplet->makeCRLPolicyDlg()->raise();
    manApplet->makeCRLPolicyDlg()->activateWindow();
}

void MainWindow::makeCertificate()
{
    manApplet->makeCertDlg()->show();
    manApplet->makeCertDlg()->raise();
    manApplet->makeCertDlg()->activateWindow();
}

void MainWindow::makeCRL()
{
    manApplet->makeCRLDlg()->show();
    manApplet->makeCRLDlg()->raise();
    manApplet->makeCRLDlg()->activateWindow();
}

void MainWindow::revokeCertificate()
{
    manApplet->revokeCertDlg()->show();
    manApplet->revokeCertDlg()->raise();
    manApplet->revokeCertDlg()->activateWindow();
}

void MainWindow::importPrivateKey()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::importEncPrivateKey()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::importRequest()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::importCertificate()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::importCRL()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::importPFX()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::exportPrivateKey()
{
    manApplet->exportDlg()->show();
    manApplet->exportDlg()->raise();
    manApplet->exportDlg()->activateWindow();
}

void MainWindow::exportEncPrivateKey()
{
    manApplet->exportDlg()->show();
    manApplet->exportDlg()->raise();
    manApplet->exportDlg()->activateWindow();
}

void MainWindow::exportRequest()
{
    manApplet->exportDlg()->show();
    manApplet->exportDlg()->raise();
    manApplet->exportDlg()->activateWindow();
}

void MainWindow::exportCertificate()
{
    manApplet->exportDlg()->show();
    manApplet->exportDlg()->raise();
    manApplet->exportDlg()->activateWindow();
}

void MainWindow::exportCRL()
{
    manApplet->exportDlg()->show();
    manApplet->exportDlg()->raise();
    manApplet->exportDlg()->activateWindow();
}

void MainWindow::exportPFX()
{
    manApplet->exportDlg()->show();
    manApplet->exportDlg()->raise();
    manApplet->exportDlg()->activateWindow();
}

void MainWindow::publishLDAP()
{
    manApplet->pubLDAPDlg()->show();
    manApplet->pubLDAPDlg()->raise();
    manApplet->pubLDAPDlg()->activateWindow();
}

void MainWindow::getLDAP()
{
    manApplet->getLDAPDlg()->show();
    manApplet->getLDAPDlg()->raise();
    manApplet->getLDAPDlg()->activateWindow();
}

void MainWindow::about()
{
    manApplet->aboutDlg()->show();
    manApplet->aboutDlg()->raise();
    manApplet->aboutDlg()->activateWindow();
}

void MainWindow::settings()
{
    manApplet->settingsDlg()->show();
    manApplet->settingsDlg()->raise();
    manApplet->settingsDlg()->activateWindow();
}

void MainWindow::deleteCertPolicy()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    db_mgr_->delCertPolicy( num );
    db_mgr_->delCertPolicyExtensionList( num );
}

void MainWindow::deleteCRLPolicy()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    db_mgr_->delCRLPolicy( num );
    db_mgr_->delCRLPolicyExtensionList( num );
}


void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}

void MainWindow::menuClick(QModelIndex index )
{
    int nType = -1;
    ManTreeItem *pItem = (ManTreeItem *)left_model_->itemFromIndex(index);

    if( pItem == NULL ) return;

    nType = pItem->getType();

    if( nType == CM_ITEM_TYPE_KEYPAIR )
        createRightKeyPairList();
    else if( nType == CM_ITEM_TYPE_REQUEST )
        createRightRequestList();
    else if( nType == CM_ITEM_TYPE_CERT_POLICY )
        createRightCertPolicyList();
    else if( nType == CM_ITEM_TYPE_CRL_POLICY )
        createRightCRLPolicyList();
    else if( nType == CM_ITEM_TYPE_ROOTCA )
        createRightCertList( -1 );
    else if( nType == CM_ITEM_TYPE_IMPORT_CERT )
        createRightCertList( -2 );
    else if( nType == CM_ITEM_TYPE_IMPORT_CRL )
        createRightCRLList( -2 );
}

void MainWindow::tableClick(QModelIndex index )
{
    int row = index.row();
    int col = index.column();

    QString strVal;

    strVal = QString( "row: %1 column %2").arg(row).arg(col);
    QTableWidgetItem* item = right_table_->item(row, 0);

    int nSeq = item->text().toInt();

    right_text_->setText( strVal );

    if( right_type_ == RightType::TYPE_KEYPAIR )
    {
        showRightKeyPair( nSeq );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        showRightRequest( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CERTIFICATE )
    {
        showRightCertificate( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        showRightCRL( nSeq );
    }
    else if( right_type_ == RightType::TYPE_REVOKE )
    {
        showRightRevoke( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CERT_POLICY )
    {
        showRightCertPolicy( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CRL_POLICY )
    {
        showRightCRLPolicy( nSeq );
    }
}

void MainWindow::createRightKeyPairList()
{
    removeAllRight();
    right_type_ = RightType::TYPE_KEYPAIR;

    QStringList headerList = { "Number", "Algorithm", "Name", "PublicKey", "PrivateKey", "Param", "Status" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(7);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<KeyPairRec> keyPairList;
    db_mgr_->getKeyPairList( keyPairList );

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        KeyPairRec keyPairRec = keyPairList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(keyPairRec.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem( keyPairRec.getAlg()));
        right_table_->setItem( i, 2, new QTableWidgetItem( keyPairRec.getName()));
        right_table_->setItem(i, 3, new QTableWidgetItem( keyPairRec.getPublicKey()));
        right_table_->setItem(i, 4, new QTableWidgetItem( keyPairRec.getPrivateKey()));
        right_table_->setItem(i, 5, new QTableWidgetItem( keyPairRec.getParam()));
        right_table_->setItem(i, 6, new QTableWidgetItem( QString("%1").arg(keyPairRec.getStatus())));
    }
}


void MainWindow::createRightRequestList()
{
    removeAllRight();
    right_type_ = RightType::TYPE_REQUEST;

    QStringList headerList = { "Seq", "KeyNum", "Name", "DN", "CSR", "Hash", "Status" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(7);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<ReqRec> reqList;
    db_mgr_->getReqList( reqList );

    for( int i=0; i < reqList.size(); i++ )
    {
        ReqRec reqRec = reqList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg( reqRec.getSeq() ) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( reqRec.getKeyNum() ) ));
        right_table_->setItem( i, 2, new QTableWidgetItem( reqRec.getName() ));
        right_table_->setItem( i, 3, new QTableWidgetItem( reqRec.getDN() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( reqRec.getCSR() ));
        right_table_->setItem( i, 5, new QTableWidgetItem( reqRec.getHash() ));
        right_table_->setItem( i, 6, new QTableWidgetItem( QString("%1").arg( reqRec.getStatus() )));
    }
}

void MainWindow::createRightCertPolicyList()
{
    removeAllRight();
    right_type_ = RightType::TYPE_CERT_POLICY;

    QStringList headerList = { "Num", "Name", "Version", "NotBerfoer", "NotAfter", "Hash", "DNTemplate" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(7);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CertPolicyRec> certPolicyList;
    db_mgr_->getCertPolicyList( certPolicyList );

    for( int i=0; i < certPolicyList.size(); i++ )
    {
        CertPolicyRec certPolicy = certPolicyList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(certPolicy.getNum()) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( certPolicy.getName() ));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg(certPolicy.getVersion() )));
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg(certPolicy.getNotBefore() )));
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg(certPolicy.getNotAfter() )));
        right_table_->setItem( i, 5, new QTableWidgetItem( certPolicy.getHash() ));
        right_table_->setItem( i, 6, new QTableWidgetItem( certPolicy.getDNTemplate() ));
    }
}

void MainWindow::createRightCRLPolicyList()
{
    removeAllRight();
    right_type_ = RightType::TYPE_CRL_POLICY;

    QStringList headerList = { "Num", "Name", "Version", "LastUpdate", "NextUpdate", "Hash" };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(6);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);


    QList<CRLPolicyRec> crlPolicyList;
    db_mgr_->getCRLPolicyList( crlPolicyList );

    for( int i=0; i < crlPolicyList.size(); i++ )
    {
        CRLPolicyRec crlPolicy = crlPolicyList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crlPolicy.getNum() )) );
        right_table_->setItem( i, 1, new QTableWidgetItem( crlPolicy.getName()) );
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg(crlPolicy.getVersion() )) );
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg(crlPolicy.getLastUpdate())) );
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg(crlPolicy.getNextUpdate())) );
        right_table_->setItem( i, 5, new QTableWidgetItem( crlPolicy.getHash()) );
    }
}

void MainWindow::createRightCertList( int nIssuerNum )
{
    removeAllRight();
    right_type_ = RightType::TYPE_CERTIFICATE;

    QStringList headerList = { "Num", "KeyNum", "SignAlg", "Cert", "IsSelf", "IsCA", "IssuerNum", "SubjectDN", "Status" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(9);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);


    QList<CertRec> certList;
    db_mgr_->getCertList( nIssuerNum, certList );

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec cert = certList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg( cert.getNum()) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( cert.getKeyNum() )));
        right_table_->setItem( i, 2, new QTableWidgetItem( cert.getSignAlg() ));
        right_table_->setItem( i, 3, new QTableWidgetItem( cert.getCert() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg( cert.isSelf())));
        right_table_->setItem( i, 5, new QTableWidgetItem( QString("%1").arg( cert.isCA() )));
        right_table_->setItem( i, 6, new QTableWidgetItem( QString("%1").arg( cert.getIssuerNum() )));
        right_table_->setItem( i, 7, new QTableWidgetItem( cert.getSubjectDN() ));
        right_table_->setItem( i, 8, new QTableWidgetItem( QString("%1").arg( cert.getStatus() )));
    }
}

void MainWindow::createRightCRLList( int nIssuerNum )
{
    removeAllRight();
    right_type_ = RightType::TYPE_CRL;

    QStringList headerList = { "Num", "IssuerNum", "SignAlg", "CRL" };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(4);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CRLRec> crlList;
    db_mgr_->getCRLList( nIssuerNum, crlList );

    for( int i=0; i < crlList.size(); i++ )
    {
        CRLRec crl = crlList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crl.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(crl.getIssuerNum() )));
        right_table_->setItem( i, 2, new QTableWidgetItem( crl.getSignAlg() ));
        right_table_->setItem( i, 3, new QTableWidgetItem( crl.getCRL() ));
    }
}

void MainWindow::showRightKeyPair( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    KeyPairRec keyPair;

    db_mgr_->getKeyPairRec( seq, keyPair );

    strMsg = "[ KeyPair information ]\n";
    strPart = QString( "Num:%1\n\n").arg( keyPair.getNum() );
    strMsg += strPart;

    strPart = QString( "Algorithm: %1\n").arg( keyPair.getAlg());
    strMsg += strPart;

    strPart = QString( "Name: %1\n").arg( keyPair.getName());
    strMsg += strPart;

    strPart = QString( "PublicKey: %1\n").arg( keyPair.getPublicKey());
    strMsg += strPart;

    strPart = QString( "PrivateKey: %1\n").arg( keyPair.getPrivateKey());
    strMsg += strPart;

    strPart = QString( "Param: %1\n").arg( keyPair.getParam());
    strMsg += strPart;

    strPart = QString( "Status: %1\n").arg( keyPair.getStatus());
    strMsg += strPart;

    right_text_->setText(strMsg);
}

void MainWindow::showRightRequest( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    ReqRec reqRec;
    db_mgr_->getReqRec( seq, reqRec );

    strMsg = "[ Request information ]\n";

    strPart = QString( "SEQ: %1\n").arg(reqRec.getSeq());
    strMsg += strPart;

    strPart = QString( "KeyNum: %1\n").arg(reqRec.getKeyNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n").arg( reqRec.getName() );
    strMsg += strPart;

    strPart = QString( "DN: %1\n").arg( reqRec.getDN());
    strMsg += strPart;

    strPart = QString( "Request: %1\n").arg( reqRec.getCSR() );
    strMsg + strPart;

    strPart = QString( "Hash: %1\n").arg( reqRec.getHash());
    strMsg += strPart;

    strPart = QString( "Status: %1").arg( reqRec.getStatus());
    strMsg += strPart;

    right_text_->setText(strMsg);
}

void MainWindow::showRightCertificate( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    CertRec certRec;
    db_mgr_->getCertRec( seq, certRec );

    strMsg = "[ Ceritificate information ]\n";

    strPart = QString("Num: %1").arg( certRec.getNum() );
    strMsg += strPart;

    strPart = QString( "KeyNum: %1").arg( certRec.getKeyNum() );
    strMsg += strPart;

    strPart = QString( "SignAlgorithm: %1").arg( certRec.getSignAlg() );
    strMsg += strPart;

    strPart = QString( "Certificate: %1").arg( certRec.getCert() );
    strMsg += strPart;

    strPart = QString( "IsCA: %1").arg( certRec.isCA() );
    strMsg += strPart;

    strPart = QString( "IsSelf: %1").arg( certRec.isSelf() );
    strMsg += strPart;

    strPart = QString( "SubjectDN: %1").arg( certRec.getSubjectDN() );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1").arg( certRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "Status: %1").arg( certRec.getStatus() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightCertPolicy( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    CertPolicyRec certPolicy;

    db_mgr_->getCertPolicyRec( seq, certPolicy );

    strMsg = "[ Certificate policy information ]\n";

    strPart = QString( "Num: %1\n").arg( certPolicy.getNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n").arg( certPolicy.getName());
    strMsg += strPart;

    strPart = QString( "Version: %1\n").arg(certPolicy.getVersion());
    strMsg += strPart;

    strPart = QString( "NotBefore: %1\n").arg(certPolicy.getNotBefore());
    strMsg += strPart;

    strPart = QString( "NotAfter: %1\n").arg( certPolicy.getNotAfter());
    strMsg += strPart;

    strPart = QString( "Hash: %1\n").arg(certPolicy.getHash());
    strMsg += strPart;

    strPart = QString( "DNTemplate: %1\n").arg( certPolicy.getDNTemplate() );
    strMsg += strPart;

    strMsg += "========= Extensions information ==========\n";

    QList<PolicyExtRec> extList;
    db_mgr_->getCertPolicyExtensionList( seq, extList );

    for( int i = 0; i < extList.size(); i++ )
    {
        PolicyExtRec extRec = extList.at(i);

        strPart = QString( "%1 || %2 || %3 || %4\n")
                .arg(extRec.getSeq())
                .arg(extRec.isCritical())
                .arg(extRec.getSN())
                .arg(extRec.getValue());

        strMsg += strPart;
    }

    right_text_->setText( strMsg );
}

void MainWindow::showRightCRL( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    CRLRec crlRec;

    db_mgr_->getCRLRec( seq, crlRec );

    strMsg = "[ CRL information ]\n";

    strPart = QString( "Num: %1\n" ).arg( crlRec.getNum() );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1\n").arg( crlRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "SignAlgorithm: %1\n").arg(crlRec.getSignAlg());
    strMsg += strPart;

    strPart = QString( "CRL: %1\n").arg( crlRec.getCRL());
    strMsg += strPart;

    /* need for revoked list information */
    // strPart = "============= Revoked List ==============\n";
    // strMsg += strPart;



    right_text_->setText( strMsg );
}

void MainWindow::showRightCRLPolicy( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    CRLPolicyRec crlPolicy;

    db_mgr_->getCRLPolicyRec( seq, crlPolicy );

    strMsg = "[ CRL information ]\n";

    strPart = QString( "Num: %1\n").arg(crlPolicy.getNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n").arg( crlPolicy.getName());
    strMsg += strPart;

    strPart = QString( "Version: %1\n").arg( crlPolicy.getVersion());
    strMsg += strPart;

    strPart = QString( "LastUpdate : %1\n").arg(crlPolicy.getLastUpdate());
    strMsg += strPart;

    strPart = QString("NextUpdate: %1\n").arg(crlPolicy.getNextUpdate());
    strMsg += strPart;

    strPart = QString("Hash: %1\n").arg(crlPolicy.getHash());
    strMsg += strPart;

    strMsg += "========= Extensions information ==========\n";

    QList<PolicyExtRec> extList;
    db_mgr_->getCRLPolicyExtensionList( seq, extList );

    for( int i = 0; i < extList.size(); i++ )
    {
        PolicyExtRec extRec = extList.at(i);

        strPart = QString( "%1 || %2 || %3 || %4\n")
                .arg(extRec.getSeq())
                .arg(extRec.isCritical())
                .arg(extRec.getSN())
                .arg(extRec.getValue());

        strMsg += strPart;
    }

    right_text_->setText(strMsg);
}

void MainWindow::showRightRevoke( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    RevokeRec revokeRec;
    db_mgr_->getRevokeRec( seq, revokeRec );

    strMsg = "[ Revoke information ]\n";

    strPart = QString( "Seq: %1\n").arg( revokeRec.getSeq());
    strMsg += strPart;

    strPart = QString( "CertNum: %1\n").arg( revokeRec.getCertNum() );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1\n").arg( revokeRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "Serial: %1\n").arg( revokeRec.getSerial() );
    strMsg += strPart;

    strPart = QString( "RevokeDate: %1\n").arg( revokeRec.getRevokeDate());
    strMsg += strPart;

    strPart = QString( "Reason: %1\n").arg( revokeRec.getReason() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}
