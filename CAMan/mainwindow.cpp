#include <QFileDialog>
#include <QtWidgets>

#include "commons.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "man_tree_item.h"
#include "man_tree_model.h"
#include "man_tree_view.h"
#include "search_menu.h"

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
#include "cert_info_dlg.h"
#include "crl_info_dlg.h"

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
#include "check_cert_dlg.h"
#include "user_rec.h"
#include "user_dlg.h"
#include "signer_dlg.h"
#include "signer_rec.h"
#include "server_status_dlg.h"
#include "man_tray_icon.h"

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
    right_num_ = -1;
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
    right_menu_ = new SearchMenu;

    left_tree_->setModel(left_model_);


    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget(vsplitter_);
    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget(right_menu_);
    vsplitter_->addWidget(right_text_);

    QList <int> vsizes;
    vsizes << 1200 << 10 << 500;
    vsplitter_->setSizes(vsizes);

    QList <int> sizes;
    sizes << 500 << 1200;
    resize(1024,768);

    hsplitter_->setSizes(sizes);
    setCentralWidget(hsplitter_);

    connect( left_tree_, SIGNAL(clicked(QModelIndex)), this, SLOT(treeMenuClick(QModelIndex)));
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

#ifdef _PRO
    QAction *regUserAct = toolsMenu->addAction(tr("&RegisterUser"), this, &MainWindow::registerUser );
    regUserAct->setStatusTip(tr("Register User"));

    QAction *regSignerAct = toolsMenu->addAction(tr("&RegisterSigner"), this, &MainWindow::registerSigner);
    regSignerAct->setStatusTip(tr("Register Signer"));
#endif

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

    QMenu *dataMenu = menuBar()->addMenu(tr("&Data"));
    QToolBar *dataToolBar = addToolBar(tr("Data"));

    QAction* importDataAct = dataMenu->addAction(tr("&ImportData"), this, &MainWindow::importData);
    importDataAct->setStatusTip(tr("Import data"));

    QAction* pubLDAPAct = dataMenu->addAction(tr("PublishLDAP"), this, &MainWindow::publishLDAP);
    pubLDAPAct->setStatusTip(tr("Publish LDAP"));

    QAction* getLDAPAct = dataMenu->addAction(tr("GetLDAP"), this, &MainWindow::getLDAP);
    getLDAPAct->setStatusTip(tr("Get LDAP"));

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

    QAction *aboutAct = helpMenu->addAction(tr("About"), this, &MainWindow::about );
    aboutAct->setStatusTip(tr("About CAMan"));

#ifdef _PRO
    QAction *srvStatusAct = helpMenu->addAction(tr("ServerStatus"), this, &MainWindow::serverStatus );
    srvStatusAct->setStatusTip(tr("Server Status Information"));
#endif

    QAction *settingsAct = helpMenu->addAction(tr("Settings"), this, &MainWindow::settings );
    settingsAct->setStatusTip(tr("Settings CAMan"));
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
//    QTableWidgetItem* item = right_table_->itemAt(point);
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );

    right_num_ = item->text().toInt();
    if( item == NULL ) return;

    QMenu menu(this);

    if( right_type_ == RightType::TYPE_CERTIFICATE)
    {
        menu.addAction( tr("Export Certificate"), this, &MainWindow::exportCertificate );
        menu.addAction( tr( "View Certificate"), this, &MainWindow::viewCertificate );
        menu.addAction( tr("Delete Certificate" ), this, &MainWindow::deleteCertificate );
        menu.addAction( tr("Revoke Certificate"), this, &MainWindow::revokeCertificate );
        menu.addAction( tr("Check Certificate"), this, &MainWindow::checkCertificate );
        menu.addAction( tr( "Publish Certificate" ), this, &MainWindow::publishLDAP );
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        menu.addAction( tr("Export CRL"), this, &MainWindow::exportCRL );
        menu.addAction( tr("View CRL"), this, &MainWindow::viewCRL );
        menu.addAction( tr("Delete CRL"), this, &MainWindow::deleteCRL );
        menu.addAction( tr("Publish CRL"), this, &MainWindow::publishLDAP );
    }
    else if( right_type_ == RightType::TYPE_KEYPAIR )
    {
        menu.addAction(tr("Export PrivateKey"), this, &MainWindow::exportPriKey );
        menu.addAction(tr("Export EncryptedPrivate"), this, &MainWindow::exportEncPriKey );
        menu.addAction(tr("Delete KeyPair"), this, &MainWindow::deleteKeyPair);
        menu.addAction(tr("Make Request"), this, &MainWindow::makeRequest );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        menu.addAction(tr("Export Request"), this, &MainWindow::exportRequest );
        menu.addAction(tr("Delete Request"), this, &MainWindow::deleteRequest );
        menu.addAction(tr("Make Certificate"), this, &MainWindow::makeCertificate );
    }
    else if( right_type_ == RightType::TYPE_CERT_POLICY )
    {
        menu.addAction(tr("Delete CertPolicy"), this, &MainWindow::deleteCertPolicy );
        menu.addAction(tr("Edit CertPolicy" ), this, &MainWindow::editCertPolicy );
    }
    else if( right_type_ == RightType::TYPE_CRL_POLICY )
    {
        menu.addAction(tr("Delete CRLPolicy"), this, &MainWindow::deleteCRLPolicy );
        menu.addAction(tr("Edit CRLPolicy"), this, &MainWindow::editCRLPolicy );
    }
    else if( right_type_ == RightType::TYPE_USER )
    {
        menu.addAction(tr("Delete User"), this, &MainWindow::deleteUser );
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        menu.addAction(tr("Delete Signer"), this, &MainWindow::deleteSigner );
    }

    menu.exec(QCursor::pos());
}

void MainWindow::createTreeMenu()
{
    left_model_->clear();
    left_tree_->header()->setVisible(false);

    ManTreeItem *pRootItem = (ManTreeItem *)left_model_->invisibleRootItem();

    ManTreeItem *pTopItem = new ManTreeItem( QString( "CAManager" ) );
    pTopItem->setIcon(QIcon(":/images/man.png"));
    pRootItem->insertRow( 0, pTopItem );

    ManTreeItem *pKeyPairItem = new ManTreeItem( QString("KeyPair") );
    pKeyPairItem->setIcon(QIcon(":/images/key.jpeg"));
    pKeyPairItem->setType( CM_ITEM_TYPE_KEYPAIR );
    pTopItem->appendRow( pKeyPairItem );

    ManTreeItem *pCSRItem = new ManTreeItem( QString("Request"));
    pCSRItem->setIcon(QIcon(":/images/csr.jpg"));
    pCSRItem->setType( CM_ITEM_TYPE_REQUEST );
    pTopItem->appendRow( pCSRItem );

#ifdef _PRO
    ManTreeItem *pUserItem = new ManTreeItem( QString("User") );
    pUserItem->setIcon(QIcon(":/images/user.jpg"));
    pUserItem->setType( CM_ITEM_TYPE_USER );
    pTopItem->appendRow( pUserItem );

    ManTreeItem *pRegSignerItem = new ManTreeItem( QString("REGSigner") );
    pRegSignerItem->setIcon(QIcon(":/images/reg_signer.png"));
    pRegSignerItem->setType( CM_ITEM_TYPE_REG_SIGNER );
    pTopItem->appendRow( pRegSignerItem );

    ManTreeItem *pOCSPSignerItem = new ManTreeItem( QString("OCSPSigner") );
    pOCSPSignerItem->setIcon(QIcon(":/images/ocsp_signer.png"));
    pOCSPSignerItem->setType( CM_ITEM_TYPE_OCSP_SIGNER );
    pTopItem->appendRow( pOCSPSignerItem );
#endif

    ManTreeItem *pCertPolicyItem = new ManTreeItem( QString("CertPolicy" ) );
    pCertPolicyItem->setIcon(QIcon(":/images/policy.png"));
    pCertPolicyItem->setType( CM_ITEM_TYPE_CERT_POLICY );
    pTopItem->appendRow( pCertPolicyItem );

    ManTreeItem *pCRLPolicyItem = new ManTreeItem( QString("CRLPolicy" ) );
    pCRLPolicyItem->setIcon(QIcon(":/images/policy.png"));
    pCRLPolicyItem->setType( CM_ITEM_TYPE_CRL_POLICY );
    pTopItem->appendRow( pCRLPolicyItem );

    ManTreeItem *pRootCAItem = new ManTreeItem( QString("RootCA") );
    pRootCAItem->setIcon( QIcon(":/images/cert.png") );
    pRootCAItem->setType(CM_ITEM_TYPE_ROOTCA);
    pRootCAItem->setDataNum(-1);
    pTopItem->appendRow( pRootCAItem );

    ManTreeItem *pImportCertItem = new ManTreeItem( QString( "ImportCert" ) );
    pImportCertItem->setIcon(QIcon(":/images/im_cert.png"));
    pImportCertItem->setType( CM_ITEM_TYPE_IMPORT_CERT );
    pTopItem->appendRow( pImportCertItem );

    ManTreeItem *pImportCRLItem = new ManTreeItem( QString( "ImportCRL" ) );
    pImportCRLItem->setIcon(QIcon(":/images/im_crl.png"));
    pImportCRLItem->setType( CM_ITEM_TYPE_IMPORT_CRL );
    pTopItem->appendRow( pImportCRLItem );

    QModelIndex ri = left_model_->index(0,0);
    left_tree_->expand(ri);

    expandItem( pRootCAItem );
}

void MainWindow::newFile()
{
    BIN binDB = {0,0};
    QString strFilter = "";

    QFile resFile( ":/ca.db" );
    resFile.open(QIODevice::ReadOnly);
    QByteArray data = resFile.readAll();
    resFile.close();

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("New DB Files"),
                                                     QDir::currentPath(),
                                                     tr("DB Files (*.db);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );

    JS_BIN_set( &binDB, (unsigned char *)data.data(), data.size() );
    JS_BIN_fileWrite( &binDB, fileName.toStdString().c_str() );
    JS_BIN_reset(&binDB);

    db_mgr_->close();
    int ret = db_mgr_->open(fileName);

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database"), this );
        return;
    }

    createTreeMenu();
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

    if( manApplet->trayIcon()->supportsMessages() )
        manApplet->trayIcon()->showMessage( "CAMan", tr("DB file is opened"), QSystemTrayIcon::Information, 10000 );
}

void MainWindow::quit()
{
    QCoreApplication::exit();
}


void MainWindow::newKey()
{
    NewKeyDlg newKeyDlg;
    newKeyDlg.exec();
}

void MainWindow::makeRequest()
{
    MakeReqDlg makeReqDlg;
    makeReqDlg.exec();
}

void MainWindow::makeCertPolicy()
{
    MakeCertPolicyDlg makeCertPolicyDlg;
    makeCertPolicyDlg.setEdit(false);
    makeCertPolicyDlg.setPolicyNum(-1);

    makeCertPolicyDlg.exec();
}

void MainWindow::makeCRLPolicy()
{
    manApplet->makeCRLPolicyDlg()->setEdit(false);
    manApplet->makeCRLPolicyDlg()->setPolicyNum(-1);

    manApplet->makeCRLPolicyDlg()->show();
    manApplet->makeCRLPolicyDlg()->raise();
    manApplet->makeCRLPolicyDlg()->activateWindow();
}

void MainWindow::editCertPolicy()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCertPolicyDlg makeCertPolicyDlg;
    makeCertPolicyDlg.setEdit(true);
    makeCertPolicyDlg.setPolicyNum(num);

    makeCertPolicyDlg.exec();
}

void MainWindow::editCRLPolicy()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->makeCRLPolicyDlg()->setEdit(true);
    manApplet->makeCRLPolicyDlg()->setPolicyNum(num);

    manApplet->makeCRLPolicyDlg()->show();
    manApplet->makeCRLPolicyDlg()->raise();
    manApplet->makeCRLPolicyDlg()->activateWindow();
}

void MainWindow::makeCertificate()
{
    MakeCertDlg makeCertDlg;
    makeCertDlg.exec();
}

void MainWindow::makeCRL()
{
    manApplet->makeCRLDlg()->show();
    manApplet->makeCRLDlg()->raise();
    manApplet->makeCRLDlg()->activateWindow();
}

void MainWindow::revokeCertificate()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    manApplet->revokeCertDlg()->setCertNum( num );
    manApplet->revokeCertDlg()->show();
    manApplet->revokeCertDlg()->raise();
    manApplet->revokeCertDlg()->activateWindow();
}

void MainWindow::registerUser()
{
    UserDlg userDlg;
    userDlg.exec();
}

void MainWindow::registerSigner()
{
    manApplet->signerDlg()->show();
    manApplet->signerDlg()->raise();
    manApplet->signerDlg()->activateWindow();
}

void MainWindow::viewCertificate()
{
    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertNum( right_num_ );
    certInfoDlg.exec();
}

void MainWindow::viewCRL()
{
    manApplet->crlInfoDlg()->setCRLNum( right_num_ );
    manApplet->crlInfoDlg()->show();
    manApplet->crlInfoDlg()->raise();
    manApplet->crlInfoDlg()->activateWindow();
}

void MainWindow::importData()
{
    manApplet->importDlg()->show();
    manApplet->importDlg()->raise();
    manApplet->importDlg()->activateWindow();
}

void MainWindow::exportPriKey()
{
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_PRIKEY );
    exportDlg.exec();
}

void MainWindow::exportEncPriKey()
{   
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_ENC_PRIKEY );
    exportDlg.exec();
}

void MainWindow::exportPubKey()
{  
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_PUBKEY );
    exportDlg.exec();
}

void MainWindow::exportRequest()
{
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_REQUEST );
    exportDlg.exec();
}

void MainWindow::exportCertificate()
{
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_CERTIFICATE );
    exportDlg.exec();
}

void MainWindow::exportCRL()
{
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_CRL );
    exportDlg.exec();
}

void MainWindow::exportPFX()
{
    ExportDlg exportDlg;
    exportDlg.setDataNum( right_num_ );
    exportDlg.setExportType( EXPORT_TYPE_PFX );
    exportDlg.exec();
}


void MainWindow::publishLDAP()
{
    PubLDAPDlg pubLDAPDlg;
    pubLDAPDlg.setDataNum( right_num_ );
    pubLDAPDlg.setDataType( right_type_ );
    pubLDAPDlg.exec();
}

void MainWindow::getLDAP()
{
    GetLDAPDlg getLDAPDlg;
    getLDAPDlg.exec();
}

void MainWindow::about()
{
    manApplet->aboutDlg()->show();
    manApplet->aboutDlg()->raise();
    manApplet->aboutDlg()->activateWindow();
}

void MainWindow::settings()
{
    SettingsDlg settingsDlg;
    settingsDlg.exec();
}

void MainWindow::serverStatus()
{
    ServerStatusDlg srvStatusDlg;
    srvStatusDlg.exec();
}

void MainWindow::deleteCertPolicy()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    db_mgr_->delCertPolicy( num );
    db_mgr_->delCertPolicyExtensionList( num );
    createRightCertPolicyList();
}

void MainWindow::deleteCRLPolicy()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    db_mgr_->delCRLPolicy( num );
    db_mgr_->delCRLPolicyExtensionList( num );
    createRightCRLPolicyList();
}

void MainWindow::deleteCertificate()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    CertRec cert;
    db_mgr_->getCertRec( num, cert );
    db_mgr_->delCertRec( num );

    createRightCertList( cert.getIssuerNum() );
}

void MainWindow::deleteCRL()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row , 0 );

    int num = item->text().toInt();

    CRLRec crl;

    db_mgr_->getCRLRec( num, crl );
    db_mgr_->delCRLRec( num );

    createRightCRLList( crl.getIssuerNum() );
}

void MainWindow::deleteKeyPair()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    db_mgr_->delKeyPairRec( num );
    createRightKeyPairList();
}

void MainWindow::deleteRequest()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    dbMgr()->delReqRec( num );
    createRightRequestList();
}

void MainWindow::deleteUser()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    dbMgr()->delUserRec( num );
    createRightUserList();
}

void MainWindow::deleteSigner()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    SignerRec signer;
    dbMgr()->getSignerRec( num, signer );
    dbMgr()->delSignerRec( num );
    createRightSignerList( signer.getType() );
}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}

void MainWindow::treeMenuClick(QModelIndex index )
{
    int nType = -1;
    int nNum = -1;

    ManTreeItem *pItem = (ManTreeItem *)left_model_->itemFromIndex(index);

    if( pItem == NULL ) return;

    nNum = pItem->getDataNum();
    nType = pItem->getType();

    right_menu_->setLeftNum( nNum );
    right_menu_->setLeftType( nType );

    createRightList( nType, nNum );
}

void MainWindow::tableClick(QModelIndex index )
{
    int row = index.row();
    int col = index.column();

    QString strVal;

    strVal = QString( "row: %1 column %2").arg(row).arg(col);
    QTableWidgetItem* item = right_table_->item(row, 0);

    int nSeq = item->text().toInt();
    right_num_ = item->text().toInt();

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
    else if( right_type_ == RightType::TYPE_USER )
    {
        showRightUser( nSeq );
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        showRightSigner( nSeq );
    }
}

void MainWindow::expandMenu()
{
    ManTreeItem* item = left_tree_->currentItem();
    expandItem( item );
}

void MainWindow::expandItem( ManTreeItem *item )
{
    int nIssuerNum = item->getDataNum();

    QList<CertRec> certList;
    db_mgr_->getCACertList( nIssuerNum, certList );

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec certRec = certList.at(i);

        ManTreeItem *pCAItem = new ManTreeItem( certRec.getSubjectDN() );
        pCAItem->setType( CM_ITEM_TYPE_CA );
        pCAItem->setDataNum( certRec.getNum() );
        item->appendRow( pCAItem );

        ManTreeItem *pCertItem = new ManTreeItem( QString("Certificate"));
        pCertItem->setType( CM_ITEM_TYPE_CERT );
        pCertItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pCertItem );

        ManTreeItem *pCRLItem = new ManTreeItem( QString("CRL") );
        pCRLItem->setType( CM_ITEM_TYPE_CRL );
        pCRLItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pCRLItem );

        ManTreeItem *pRevokeItem = new ManTreeItem( QString("Revoke"));
        pRevokeItem->setType( CM_ITEM_TYPE_REVOKE );
        pRevokeItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pRevokeItem );

        ManTreeItem *pSubCAItem = new ManTreeItem( QString("CA"));
        pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
        pSubCAItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pSubCAItem );
    }

    left_tree_->expand( item->index() );
}

void MainWindow::checkCertificate()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->checkCertDlg()->setCertNum(num);
    manApplet->checkCertDlg()->show();
    manApplet->checkCertDlg()->raise();
    manApplet->checkCertDlg()->activateWindow();
}

void MainWindow::createRightList( int nType, int nNum )
{
    if( nType == CM_ITEM_TYPE_CRL_POLICY ||
            nType == CM_ITEM_TYPE_CERT_POLICY ||
            nType == CM_ITEM_TYPE_OCSP_SIGNER ||
            nType == CM_ITEM_TYPE_REG_SIGNER )
    {
        right_menu_->hide();
    }
    else
        right_menu_->show();

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
    else if( nType == CM_ITEM_TYPE_CA )
        createRightCertList( nNum, true );
    else if( nType == CM_ITEM_TYPE_CERT )
        createRightCertList( nNum );
    else if( nType == CM_ITEM_TYPE_CRL )
        createRightCRLList( nNum );
    else if( nType == CM_ITEM_TYPE_SUBCA )
        createRightCertList( nNum, true );
    else if( nType == CM_ITEM_TYPE_REVOKE )
        createRightRevokeList( nNum );
    else if( nType == CM_ITEM_TYPE_USER )
        createRightUserList();
    else if( nType == CM_ITEM_TYPE_REG_SIGNER )
        createRightSignerList( SIGNER_TYPE_REG );
    else if( nType == CM_ITEM_TYPE_OCSP_SIGNER )
        createRightSignerList( SIGNER_TYPE_OCSP );
}

void MainWindow::createRightKeyPairList()
{
    removeAllRight();
    right_type_ = RightType::TYPE_KEYPAIR;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = { "Number", "Algorithm", "Name", "PublicKey", "PrivateKey", "Param", "Status" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<KeyPairRec> keyPairList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getKeyPairSearchCount( -1,  strTarget, strWord );
        db_mgr_->getKeyPairList( -1, strTarget, strWord, nOffset, nLimit, keyPairList );
    }
    else
    {
        nTotalCount = db_mgr_->getKeyPairCount( -1 );
        db_mgr_->getKeyPairList( -1, nOffset, nLimit, keyPairList );
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->setListCount( keyPairList.size() );
    right_menu_->updatePageLabel();


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

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = { "Seq", "KeyNum", "Name", "Hash", "Status", "DN" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(6);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<ReqRec> reqList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getReqSearchCount( -1,  strTarget, strWord );
        db_mgr_->getReqList( -1, strTarget, strWord, nOffset, nLimit, reqList );
    }
    else
    {
        nTotalCount = db_mgr_->getReqCount( -1 );
        db_mgr_->getReqList( -1, nOffset, nLimit, reqList );
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->setListCount( reqList.size() );
    right_menu_->updatePageLabel();


    for( int i=0; i < reqList.size(); i++ )
    {
        ReqRec reqRec = reqList.at(i);

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg( reqRec.getSeq() ) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( reqRec.getKeyNum() ) ));
        right_table_->setItem( i, 2, new QTableWidgetItem( reqRec.getName() ));
        right_table_->setItem( i, 3, new QTableWidgetItem( reqRec.getHash() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg( reqRec.getStatus() )));
        right_table_->setItem( i, 5, new QTableWidgetItem( reqRec.getDN() ));
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

void MainWindow::createRightCertList( int nIssuerNum, bool bIsCA )
{
    removeAllRight();
    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    right_type_ = RightType::TYPE_CERTIFICATE;

//    QStringList headerList = { "Num", "KeyNum", "SignAlg", "Cert", "IsSelf", "IsCA", "IssuerNum", "SubjectDN", "Status" };
    QStringList headerList = { "Num", "KeyNum", "SignAlg", "Cert", "IssuerNum", "SubjectDN" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QList<CertRec> certList;


    if( bIsCA )
    {
        if( strWord.length() > 0 )
            db_mgr_->getCACertList( nIssuerNum, strTarget, strWord, certList );
        else
            db_mgr_->getCACertList( nIssuerNum, certList );

        nTotalCount = certList.size();
    }
    else
    {
        if( strWord.length() > 0 )
        {
            nTotalCount = db_mgr_->getCertSearchCount( nIssuerNum,  strTarget, strWord );
            db_mgr_->getCertList( nIssuerNum, strTarget, strWord, nOffset, nLimit, certList );
        }
        else
        {
            nTotalCount = db_mgr_->getCertCount( nIssuerNum );
            db_mgr_->getCertList( nIssuerNum, nOffset, nLimit, certList );
        }
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->setListCount( certList.size() );
    right_menu_->updatePageLabel();

    for( int i=0; i < certList.size(); i++ )
    {
        int pos = 0;
        CertRec cert = certList.at(i);

        QString strDNInfo;
        if( cert.isSelf() ) strDNInfo += "[Self]";
        if( cert.isCA() ) strDNInfo += "[CA]";
        strDNInfo += QString( "[%1] " ).arg( cert.getStatus() );
        strDNInfo += cert.getSubjectDN();

        right_table_->insertRow(i);
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getNum()) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getKeyNum() )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( cert.getSignAlg() ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( cert.getCert() ));
//        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.isSelf())));
//        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.isCA() )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getIssuerNum() )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( strDNInfo ));
//        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getStatus() )));
    }
}

void MainWindow::createRightCRLList( int nIssuerNum )
{
    removeAllRight();
    right_type_ = RightType::TYPE_CRL;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = { "Num", "IssuerNum", "SignAlg", "CRL" };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CRLRec> crlList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getCRLSearchCount( nIssuerNum,  strTarget, strWord );
        db_mgr_->getCRLList( nIssuerNum, strTarget, strWord, nOffset, nLimit, crlList );
    }
    else
    {
        nTotalCount = db_mgr_->getCRLCount( nIssuerNum );
        db_mgr_->getCRLList( nIssuerNum, nOffset, nLimit, crlList );
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->setListCount( crlList.size() );
    right_menu_->updatePageLabel();

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

void MainWindow::createRightRevokeList(int nIssuerNum)
{
    removeAllRight();
    right_type_ = RightType::TYPE_REVOKE;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = {"Num", "CertNum", "IssuerNum", "Serial", "RevokeDate", "Reason" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<RevokeRec> revokeList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getRevokeSearchCount( nIssuerNum,  strTarget, strWord );
        db_mgr_->getRevokeList( nIssuerNum, strTarget, strWord, nOffset, nLimit, revokeList );
    }
    else
    {
        nTotalCount = db_mgr_->getRevokeCount( nIssuerNum );
        db_mgr_->getRevokeList( nIssuerNum, nOffset, nLimit, revokeList );
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->setListCount( revokeList.size() );
    right_menu_->updatePageLabel();


    for( int i=0; i < revokeList.size(); i++ )
    {
        RevokeRec revoke = revokeList.at(i);

        right_table_->insertRow(i);

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg(revoke.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg(revoke.getCertNum())));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg(revoke.getIssuerNum())));
        right_table_->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(revoke.getSerial())));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg(revoke.getRevokeDate())));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg(revoke.getReason())));
    }
}

void MainWindow::createRightUserList()
{
    removeAllRight();
    right_type_ = RightType::TYPE_USER;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = {"Num", "Name", "SSN", "Email", "Status", "RefCode", "SecretNum" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<UserRec> userList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getUserSearchCount( strTarget, strWord );
        db_mgr_->getUserList( strTarget, strWord, nOffset, nLimit, userList );
    }
    else
    {
        nTotalCount = db_mgr_->getUserCount();
        db_mgr_->getUserList( nOffset, nLimit, userList );
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->setListCount( userList.size() );
    right_menu_->updatePageLabel();

    db_mgr_->getUserList( userList );

    for( int i = 0; i < userList.size(); i++ )
    {
        UserRec user = userList.at(i);
        right_table_->insertRow(i);

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( user.getNum() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( user.getName())));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( user.getSSN() )));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( user.getEmail() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( user.getStatus() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( user.getRefCode() )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg( user.getSecretNum() )));
    }
}

void MainWindow::createRightSignerList(int nType)
{
    removeAllRight();
    right_type_ = RightType::TYPE_SIGNER;

    QStringList headerList = { "Num", "Type", "DN", "Status", "Cert" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);

    right_table_->setColumnCount(5);
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<SignerRec> signerList;
    db_mgr_->getSignerList( nType, signerList );

    for( int i = 0; i < signerList.size(); i++ )
    {
        SignerRec signer = signerList.at(i);
        right_table_->insertRow(i);

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( signer.getNum() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( signer.getType() )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( signer.getDN() )));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( signer.getStatus() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( signer.getCert() )));
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
    strMsg += strPart;

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

    strPart = QString("Num: %1\n").arg( certRec.getNum() );
    strMsg += strPart;

    strPart = QString( "KeyNum: %1\n").arg( certRec.getKeyNum() );
    strMsg += strPart;

    strPart = QString( "SignAlgorithm: %1\n").arg( certRec.getSignAlg() );
    strMsg += strPart;

    strPart = QString( "Certificate: %1\n").arg( certRec.getCert() );
    strMsg += strPart;

    strPart = QString( "IsCA: %1\n").arg( certRec.isCA() );
    strMsg += strPart;

    strPart = QString( "IsSelf: %1\n").arg( certRec.isSelf() );
    strMsg += strPart;

    strPart = QString( "SubjectDN: %1\n").arg( certRec.getSubjectDN() );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1\n").arg( certRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "Status: %1\n").arg( certRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "Serial: %1\n").arg( certRec.getSerial() );
    strMsg += strPart;

    strPart = QString( "DNHash: %1\n").arg( certRec.getDNHash() );
    strMsg += strPart;

    strPart = QString( "KeyHash: %1\n").arg( certRec.getKeyHash() );
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

void MainWindow::showRightUser( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    UserRec userRec;
    db_mgr_->getUserRec( seq, userRec );

    strMsg = "[ User information ]\n";

    strPart = QString( "Num: %1\n").arg( userRec.getNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n").arg( userRec.getName() );
    strMsg += strPart;

    strPart = QString( "SSN: %1\n").arg( userRec.getSSN() );
    strMsg += strPart;

    strPart = QString( "Email: %1\n").arg( userRec.getEmail() );
    strMsg += strPart;

    strPart = QString( "Status: %1\n").arg( userRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "RefCode: %1\n").arg( userRec.getRefCode() );
    strMsg += strPart;

    strPart = QString( "SecretNum: %1\n").arg( userRec.getSecretNum() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightSigner(int seq)
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    SignerRec signerRec;
    db_mgr_->getSignerRec( seq, signerRec );

    strMsg = "[ Signer information ]\n";

    strPart = QString( "Num: %1\n").arg( signerRec.getNum());
    strMsg += strPart;

    strPart = QString( "Type: %1\n").arg( signerRec.getType() );
    strMsg += strPart;

    strPart = QString( "DN: %1\n").arg( signerRec.getDN() );
    strMsg += strPart;

    strPart = QString( "DNHash: %1\n").arg( signerRec.getDNHash() );
    strMsg += strPart;

    strPart = QString( "Cert: %1\n").arg( signerRec.getCert() );
    strMsg += strPart;

    strPart = QString( "Status: %1\n").arg( signerRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "Desc: %1\n").arg( signerRec.getDesc());
    strMsg += strPart;

    right_text_->setText( strMsg );
}
