#include <QFileDialog>
#include <QtWidgets>

#include "js_util.h"
#include "js_gen.h"

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
#include "kms_rec.h"
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
#include "statistics_form.h"
#include "stat_form.h"
#include "audit_rec.h"

const int kMaxRecentFiles = 10;

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
    root_ca_ = NULL;
}

MainWindow::~MainWindow()
{
    delete hsplitter_;
    delete vsplitter_;
    delete left_tree_;
    delete left_model_;
    delete right_text_;
    delete right_table_;
    delete right_menu_;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    if( db_mgr_->isOpen() )
    {
        manApplet->warningBox( tr("Database has already opened"), this );
        return;
    }

    foreach (const QUrl &url, event->mimeData()->urls()) {
        QString fileName = url.toLocalFile();
        qDebug() << "Dropped file:" << fileName;
        openDB(fileName);
        setTitle( fileName );
        return;
    }
}

void MainWindow::setTitle(const QString strName)
{
    QString strWinTitle = QString( "%1 - %2").arg( manApplet->getBrand() ).arg( strName );
    setWindowTitle(strWinTitle);
}

ManTreeItem* MainWindow::currentItem()
{
    ManTreeItem *item = NULL;
    QModelIndex index = left_tree_->currentIndex();

    item = (ManTreeItem *)left_model_->itemFromIndex( index );

    return item;
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

    QWidget *rightWidget = new QWidget;
    // QScrollArea *rightWidget = new QScrollArea;

    stack_ = new QStackedLayout();
    statistics_ = new StatisticsForm;
    stat_ = new StatForm;

    stack_->addWidget( vsplitter_ );
//    stack_->addWidget( statistics_ );
    stack_->addWidget( stat_ );
    rightWidget->setLayout(stack_);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget( rightWidget );

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
    connect( left_tree_, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(treeMenuDoubleClick(QModelIndex)));
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

    QAction* recentFileAct = NULL;
    for( auto i = 0; i < kMaxRecentFiles; ++i )
    {
        recentFileAct = new QAction(this);
        recentFileAct->setVisible(false);

        QObject::connect( recentFileAct, &QAction::triggered, this, &MainWindow::openRecent );
        recent_file_list_.append( recentFileAct );
    }

    QMenu* recentMenu = fileMenu->addMenu( tr("Recent Files" ) );
    for( int i = 0; i < kMaxRecentFiles; i++ )
    {
        recentMenu->addAction( recent_file_list_.at(i) );
    }

    updateRecentActionList();

    fileMenu->addSeparator();

    QAction *quitAct = new QAction(tr("&Quit"), this );
    quitAct->setStatusTip( tr("Quit CAManager") );
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction( quitAct );

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    QToolBar *toolsToolBar = addToolBar(tr("Tools"));

    const QIcon newKeyIcon = QIcon::fromTheme("new-key", QIcon(":/images/key.jpeg"));
    QAction *newKeyAct = new QAction( newKeyIcon, tr("&NewKey"), this );
    newKeyAct->setStatusTip(tr("Generate new key pair"));
    connect( newKeyAct, &QAction::triggered, this, &MainWindow::newKey );
    toolsMenu->addAction( newKeyAct );
    toolsToolBar->addAction( newKeyAct );


    QAction *makeReqAct = toolsMenu->addAction(tr("&MakeRequest"), this, &MainWindow::makeRequest);
    makeReqAct->setStatusTip(tr( "Make Request"));

#ifdef _PRO
    QAction *regUserAct = toolsMenu->addAction(tr("&RegisterUser"), this, &MainWindow::registerUser );
    regUserAct->setStatusTip(tr("Register User"));

    QAction *regSignerAct = toolsMenu->addAction(tr("&RegisterSigner"), this, &MainWindow::registerSigner);
    regSignerAct->setStatusTip(tr("Register Signer"));
#endif

    const QIcon certPolicyIcon = QIcon::fromTheme("cert-policy", QIcon(":/images/cert_policy.png"));
    QAction *makeCertPolicyAct = new QAction( certPolicyIcon, tr("&MakeCertPolicy"), this );
    makeCertPolicyAct->setStatusTip(tr( "Make certificate policy"));
    connect( makeCertPolicyAct, &QAction::triggered, this, &MainWindow::makeCertPolicy );
    toolsMenu->addAction( makeCertPolicyAct );
    toolsToolBar->addAction( makeCertPolicyAct );

    const QIcon crlPolicyIcon = QIcon::fromTheme("crl-policy", QIcon(":/images/crl_policy.png"));
    QAction *makeCRLPolicyAct = new QAction( crlPolicyIcon, tr("&MakeCRLPolicy"), this );
    connect( makeCRLPolicyAct, &QAction::triggered, this, &MainWindow::makeCRLPolicy);
    toolsMenu->addAction( makeCRLPolicyAct );
    toolsToolBar->addAction( makeCRLPolicyAct );
    makeCRLPolicyAct->setStatusTip(tr( "Make CRL Policy"));

    QAction *makeCertAct = toolsMenu->addAction(tr("&MakeCertificate"), this, &MainWindow::makeCertificate);
    makeCertAct->setStatusTip(tr( "Make certificate"));

    QAction *makeCRLAct = toolsMenu->addAction(tr("&MakeCRL"), this, &MainWindow::makeCRL );
    makeCRLAct->setStatusTip(tr( "Make CRL"));

    QAction *revokeCertAct = toolsMenu->addAction(tr("&RevokeCert"), this, &MainWindow::revokeCertificate);
    revokeCertAct->setStatusTip(tr( "Revoke certificate"));

    QMenu *dataMenu = menuBar()->addMenu(tr("&Data"));
    QToolBar *dataToolBar = addToolBar(tr("Data"));

    const QIcon diskIcon = QIcon::fromTheme("disk", QIcon(":/images/disk.png"));
    QAction* importDataAct = new QAction( diskIcon, tr("&ImportData"), this );
    connect( importDataAct, &QAction::triggered, this, &MainWindow::importData );
    dataMenu->addAction( importDataAct );
    dataToolBar->addAction( importDataAct );
    importDataAct->setStatusTip(tr("Import data"));

    QAction* pubLDAPAct = dataMenu->addAction(tr("PublishLDAP"), this, &MainWindow::publishLDAP);
    pubLDAPAct->setStatusTip(tr("Publish LDAP"));

    QAction* getLDAPAct = dataMenu->addAction(tr("GetLDAP"), this, &MainWindow::getLDAP);
    getLDAPAct->setStatusTip(tr("Get LDAP"));

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

    const QIcon caManIcon = QIcon::fromTheme("caman", QIcon(":/images/caman.png"));
    QAction *aboutAct = new QAction( caManIcon, tr("About CAMan"), this);
    connect( aboutAct, &QAction::triggered, this, &MainWindow::about);
    helpMenu->addAction( aboutAct );
    helpToolBar->addAction( aboutAct );
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
        menu.addAction( tr("Status Certificate"), this, &MainWindow::certStatus );
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
    pCertPolicyItem->setIcon(QIcon(":/images/cert_policy.png"));
    pCertPolicyItem->setType( CM_ITEM_TYPE_CERT_POLICY );
    pTopItem->appendRow( pCertPolicyItem );

    ManTreeItem *pCRLPolicyItem = new ManTreeItem( QString("CRLPolicy" ) );
    pCRLPolicyItem->setIcon(QIcon(":/images/crl_policy.png"));
    pCRLPolicyItem->setType( CM_ITEM_TYPE_CRL_POLICY );
    pTopItem->appendRow( pCRLPolicyItem );

    ManTreeItem *pRootCAItem = new ManTreeItem( QString("RootCA") );
    pRootCAItem->setIcon( QIcon(":/images/cert.png") );
    pRootCAItem->setType(CM_ITEM_TYPE_ROOTCA);
    pRootCAItem->setDataNum(-1);
    pTopItem->appendRow( pRootCAItem );
    expandItem( pRootCAItem );
    root_ca_ = pRootCAItem;

    ManTreeItem *pImportCertItem = new ManTreeItem( QString( "ImportCert" ) );
    pImportCertItem->setIcon(QIcon(":/images/im_cert.png"));
    pImportCertItem->setType( CM_ITEM_TYPE_IMPORT_CERT );
    pTopItem->appendRow( pImportCertItem );

    ManTreeItem *pImportCRLItem = new ManTreeItem( QString( "ImportCRL" ) );
    pImportCRLItem->setIcon(QIcon(":/images/im_crl.png"));
    pImportCRLItem->setType( CM_ITEM_TYPE_IMPORT_CRL );
    pTopItem->appendRow( pImportCRLItem );

    ManTreeItem *pKMSItem = new ManTreeItem( QString( "KMS" ));
    pKMSItem->setIcon(QIcon(":/images/kms.png"));
    pKMSItem->setType( CM_ITEM_TYPE_KMS );
    pTopItem->appendRow( pKMSItem );

    ManTreeItem *pStatisticsItem = new ManTreeItem( QString( "Statistics" ));
    pStatisticsItem->setIcon(QIcon(":/images/statistics.png"));
    pStatisticsItem->setType( CM_ITEM_TYPE_STATISTICS );
    pTopItem->appendRow( pStatisticsItem );

    ManTreeItem *pAuditItem = new ManTreeItem( QString( "Audit") );
    pAuditItem->setIcon( QIcon(":/images/audit.png"));
    pAuditItem->setType( CM_ITEM_TYPE_AUDIT );
    pTopItem->appendRow( pAuditItem );


    QModelIndex ri = left_model_->index(0,0);
    left_tree_->expand(ri);

//    expandItem( pRootCAItem );
}

void MainWindow::newFile()
{
    BIN binDB = {0,0};
    QString strFilter = "";

    if( db_mgr_->isOpen() )
    {
        manApplet->warningBox( tr("Database has already openend"), this );
        return;
    }

    QFile resFile( ":/ca.db" );
    resFile.open(QIODevice::ReadOnly);
    QByteArray data = resFile.readAll();
    resFile.close();

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString strPath = getPath();

    QString selectedFilter;
    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("New CA DB Files"),
                                                     strPath,
                                                     tr("DB Files (*.db);;All Files (*)"),
                                                     &selectedFilter,
                                                     options );
    if( fileName.length() < 1 )
    {
        return;
    }

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

    setPath( fileName );
    setTitle( fileName );
    createTreeMenu();
}

int MainWindow::openDB( const QString dbPath )
{
    db_mgr_->close();
    int ret = db_mgr_->open(dbPath);

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database"), this );
        return ret;
    }

    createTreeMenu();

    if( manApplet->trayIcon()->supportsMessages() )
        manApplet->trayIcon()->showMessage( "CAMan", tr("DB file is opened"), QSystemTrayIcon::Information, 10000 );

    if( ret == 0 )
    {
        setPath( dbPath );
        setTitle( dbPath );
        adjustForCurrentFile( dbPath );
        addAudit( db_mgr_, JS_GEN_KIND_CAMAN, JS_GEN_OP_OPENDB, "" );
    }

    return ret;
}

QString MainWindow::getPath()
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

    return strPath;
}

void MainWindow::setPath( const QString strFilePath )
{
    bool bSavePath = manApplet->settingsMgr()->saveDBPath();

    if( bSavePath )
    {
        QFileInfo fileInfo( strFilePath );
        QString strDir = fileInfo.dir().path();

        QSettings settings;
        settings.beginGroup("mainwindow");
        settings.setValue( "dbPath", strDir );
        settings.endGroup();
    }
}

void MainWindow::adjustForCurrentFile( const QString& filePath )
{
    QSettings settings;
    QStringList recentFilePaths = settings.value( "recentFiles" ).toStringList();

    recentFilePaths.removeAll( filePath );
    recentFilePaths.prepend( filePath );

    while( recentFilePaths.size() > kMaxRecentFiles )
        recentFilePaths.removeLast();

    settings.setValue( "recentFiles", recentFilePaths );

    updateRecentActionList();
}

void MainWindow::updateRecentActionList()
{
    QSettings settings;
    QStringList recentFilePaths = settings.value( "recentFiles" ).toStringList();

    auto itEnd = 0u;

    if( recentFilePaths.size() <= kMaxRecentFiles )
        itEnd = recentFilePaths.size();
    else
        itEnd = kMaxRecentFiles;

    for( auto i = 0u; i < itEnd; ++i )
    {
        QString strippedName = QFileInfo(recentFilePaths.at(i)).fileName();
        recent_file_list_.at(i)->setText(strippedName);
        recent_file_list_.at(i)->setData( recentFilePaths.at(i));
        recent_file_list_.at(i)->setVisible(true);
    }

    for( auto i = itEnd; i < kMaxRecentFiles; ++i )
        recent_file_list_.at(i)->setVisible(false);
}


void MainWindow::open()
{
    if( db_mgr_->isOpen() )
    {
        manApplet->warningBox( tr("Database has already opened"), this );
        return;
    }

    QString strPath = getPath();

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Open CA DB file"),
                                                     strPath,
                                                     tr("DB Files (*.db);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() < 1 )
    {
        return;
    }

    int ret = openDB( fileName );
}

void MainWindow::openRecent()
{
    QAction *action = qobject_cast<QAction *>(sender());
    if( action )
        openDB( action->data().toString() );
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
    MakeCRLPolicyDlg makeCRLPolicyDlg;
    makeCRLPolicyDlg.setEdit(false);
    makeCRLPolicyDlg.setPolicyNum(-1);
    makeCRLPolicyDlg.exec();
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

    MakeCRLPolicyDlg makeCRLPolicyDlg;
    makeCRLPolicyDlg.setEdit(true);
    makeCRLPolicyDlg.setPolicyNum(num);
    makeCRLPolicyDlg.exec();
}

void MainWindow::makeCertificate()
{
    ManTreeItem *pItem = currentItem();

    MakeCertDlg makeCertDlg;

    if( pItem )
    {
        if( pItem->getType() == CM_ITEM_TYPE_CA )
        {
            makeCertDlg.setFixIssuer( pItem->text() );
        }
    }

    makeCertDlg.exec();
}

void MainWindow::makeCRL()
{
    ManTreeItem *pItem = currentItem();
    MakeCRLDlg makeCRLDlg;

    if( pItem )
    {
        if( pItem->getType() == CM_ITEM_TYPE_CA )
            makeCRLDlg.setFixIssuer( pItem->text() );
    }

    makeCRLDlg.exec();
}

void MainWindow::revokeCertificate()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    RevokeCertDlg revokeCertDlg;
    revokeCertDlg.setCertNum(num);
    revokeCertDlg.exec();
}

void MainWindow::registerUser()
{
    UserDlg userDlg;
    userDlg.exec();
}

void MainWindow::registerSigner()
{
    SignerDlg signerDlg;
    signerDlg.exec();
}

void MainWindow::viewCertificate()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertNum( num );
    certInfoDlg.exec();
}

void MainWindow::viewCRL()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CRLInfoDlg crlInfoDlg;
    crlInfoDlg.setCRLNum( num );
    crlInfoDlg.exec();
}

void MainWindow::importData()
{
    ImportDlg importDlg;
    importDlg.exec();
}

void MainWindow::importCert()
{
    ImportDlg importDlg;
    importDlg.setType(3);
    importDlg.exec();
}

void MainWindow::importCRL()
{
    ImportDlg importDlg;
    importDlg.setType(4);
    importDlg.exec();
}

void MainWindow::exportPriKey()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_PRIKEY );
    exportDlg.exec();
}

void MainWindow::exportEncPriKey()
{   
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_ENC_PRIKEY );
    exportDlg.exec();
}

void MainWindow::exportPubKey()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_PUBKEY );
    exportDlg.exec();
}

void MainWindow::exportRequest()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_REQUEST );
    exportDlg.exec();
}

void MainWindow::exportCertificate()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_CERTIFICATE );
    exportDlg.exec();
}

void MainWindow::exportCRL()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_CRL );
    exportDlg.exec();
}

void MainWindow::exportPFX()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_PFX );
    exportDlg.exec();
}


void MainWindow::publishLDAP()
{
    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    PubLDAPDlg pubLDAPDlg;
    pubLDAPDlg.setDataNum( num );
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

    right_menu_->setCurPage(0);
    right_menu_->setLeftNum( nNum );
    right_menu_->setLeftType( nType );

    createRightList( nType, nNum );
}

void MainWindow::treeMenuDoubleClick(QModelIndex index)
{
    ManTreeItem *pItem = (ManTreeItem *)left_model_->itemFromIndex(index);

    if( pItem == NULL ) return;

    if( pItem->getType() == CM_ITEM_TYPE_SUBCA )
    {
        if( pItem->hasChildren() == false )
            expandItem( pItem );
    }

    left_tree_->expand(index);
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
    else if( right_type_ == RightType::TYPE_USER )
    {
        showRightUser( nSeq );
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        showRightSigner( nSeq );
    }
    else if( right_type_ == RightType::TYPE_KMS )
    {
        showRightKMS( nSeq );
    }
    else if( right_type_ == RightType::TYPE_STATISTICS )
    {
        showRightStatistics();
    }
    else if( right_type_ == RightType::TYPE_AUDIT )
    {
        showRightAudit( nSeq );
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
        pCAItem->setIcon( QIcon(":/images/ca.png"));
        item->appendRow( pCAItem );

        ManTreeItem *pCertItem = new ManTreeItem( QString("Certificate"));
        pCertItem->setType( CM_ITEM_TYPE_CERT );
        pCertItem->setDataNum( certRec.getNum() );
        pCertItem->setIcon(QIcon(":/images/cert.png"));
        pCAItem->appendRow( pCertItem );

        ManTreeItem *pCRLItem = new ManTreeItem( QString("CRL") );
        pCRLItem->setType( CM_ITEM_TYPE_CRL );
        pCRLItem->setDataNum( certRec.getNum() );
        pCRLItem->setIcon(QIcon(":/images/crl.png"));
        pCAItem->appendRow( pCRLItem );

        ManTreeItem *pRevokeItem = new ManTreeItem( QString("Revoke"));
        pRevokeItem->setType( CM_ITEM_TYPE_REVOKE );
        pRevokeItem->setDataNum( certRec.getNum() );
        pRevokeItem->setIcon(QIcon(":/images/revoke.png"));
        pCAItem->appendRow( pRevokeItem );

        ManTreeItem *pSubCAItem = new ManTreeItem( QString("CA"));
        pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
        pSubCAItem->setIcon(QIcon(":/images/ca.png"));
        pSubCAItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pSubCAItem );
    }

    left_tree_->expand( item->index() );
}

void MainWindow::addRootCA( CertRec& certRec )
{
   if( root_ca_ == NULL ) return;

   ManTreeItem *pCAItem = new ManTreeItem( certRec.getSubjectDN() );
   pCAItem->setType( CM_ITEM_TYPE_CA );
   pCAItem->setDataNum( certRec.getNum() );
   pCAItem->setIcon( QIcon(":/images/ca.png"));
   root_ca_->appendRow( pCAItem );

   ManTreeItem *pCertItem = new ManTreeItem( QString("Certificate"));
   pCertItem->setType( CM_ITEM_TYPE_CERT );
   pCertItem->setDataNum( certRec.getNum() );
   pCertItem->setIcon(QIcon(":/images/cert.png"));
   pCAItem->appendRow( pCertItem );

   ManTreeItem *pCRLItem = new ManTreeItem( QString("CRL") );
   pCRLItem->setType( CM_ITEM_TYPE_CRL );
   pCRLItem->setDataNum( certRec.getNum() );
   pCRLItem->setIcon(QIcon(":/images/crl.png"));
   pCAItem->appendRow( pCRLItem );

   ManTreeItem *pRevokeItem = new ManTreeItem( QString("Revoke"));
   pRevokeItem->setType( CM_ITEM_TYPE_REVOKE );
   pRevokeItem->setDataNum( certRec.getNum() );
   pRevokeItem->setIcon(QIcon(":/images/revoke.png"));
   pCAItem->appendRow( pRevokeItem );

   ManTreeItem *pSubCAItem = new ManTreeItem( QString("CA"));
   pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
   pSubCAItem->setIcon(QIcon(":/images/ca.png"));
   pSubCAItem->setDataNum( certRec.getNum() );
   pCAItem->appendRow( pSubCAItem );

   left_tree_->expand( root_ca_->index() );
}



void MainWindow::checkCertificate()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    CheckCertDlg checkCertDlg;
    checkCertDlg.setCertNum(num);
    checkCertDlg.exec();
}

void MainWindow::certStatus()
{
    QString strStatus;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();


    CertRec certRec;
    RevokeRec   revokeRec;
    char        sRevokedDate[64];
    const char  *pReason = NULL;

    db_mgr_->getCertRec( num, certRec );

    if( certRec.getNum() <= 0 )
    {
        manApplet->warningBox( tr("fail to get certificate information"), this );
        return;
    }

    if( certRec.getStatus() > 0 )
    {
        db_mgr_->getRevokeRecByCertNum( certRec.getNum(), revokeRec );
        if( revokeRec.getSeq() <= 0 )
        {
            manApplet->warningBox( tr("fail to get revoke information"), this );
            return;
        }
    }

    if( certRec.getStatus() == 0 )
    {
        strStatus = "Good";
    }
    else
    {
        JS_UTIL_getDateTime( revokeRec.getRevokeDate(), sRevokedDate );
        pReason = JS_PKI_getRevokeReasonName( revokeRec.getReason() );
        strStatus = QString( "Revoked Reason:%1 RevokedDate: %2" ).arg( pReason ).arg( sRevokedDate );
    }

    manApplet->messageBox( strStatus, this );
}

void MainWindow::createRightList( int nType, int nNum )
{
    /*
    if( nType == CM_ITEM_TYPE_CRL_POLICY ||
            nType == CM_ITEM_TYPE_CERT_POLICY ||
            nType == CM_ITEM_TYPE_OCSP_SIGNER ||
            nType == CM_ITEM_TYPE_REG_SIGNER )
    {
        right_menu_->hide();
    }
    else
        right_menu_->show();
        */
    stack_->setCurrentIndex(0);

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
    else if( nType == CM_ITEM_TYPE_KMS )
        createRightKMSList();
    else if( nType == CM_ITEM_TYPE_STATISTICS )
        createRightStatistics();
    else if( nType == CM_ITEM_TYPE_AUDIT )
        createRightAuditList();
}

void MainWindow::createRightKeyPairList()
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_KEYPAIR;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = { "Number", "RegTime", "Algorithm", "Name", "PublicKey", "PrivateKey", "Param", "Status" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        char sRegTime[64];
        KeyPairRec keyPairRec = keyPairList.at(i);

        JS_UTIL_getDateTime( keyPairRec.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(keyPairRec.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg(sRegTime)));
        right_table_->setItem( i, 2, new QTableWidgetItem( keyPairRec.getAlg()));
        right_table_->setItem( i, 3, new QTableWidgetItem( keyPairRec.getName()));
        right_table_->setItem(i, 4, new QTableWidgetItem( keyPairRec.getPublicKey()));
        right_table_->setItem(i, 5, new QTableWidgetItem( keyPairRec.getPrivateKey()));
        right_table_->setItem(i, 7, new QTableWidgetItem( keyPairRec.getParam()));
        right_table_->setItem(i, 7, new QTableWidgetItem( QString("%1").arg(keyPairRec.getStatus())));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}


void MainWindow::createRightRequestList()
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_REQUEST;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = { "Seq", "RegTime", "KeyNum", "Name", "Hash", "Status", "DN" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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


    for( int i=0; i < reqList.size(); i++ )
    {
        char sRegTime[64];
        ReqRec reqRec = reqList.at(i);
        JS_UTIL_getDateTime( reqRec.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg( reqRec.getSeq() ) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sRegTime ) ));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( reqRec.getKeyNum() ) ));
        right_table_->setItem( i, 3, new QTableWidgetItem( reqRec.getName() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( reqRec.getHash() ));
        right_table_->setItem( i, 5, new QTableWidgetItem( QString("%1").arg( reqRec.getStatus() )));
        right_table_->setItem( i, 6, new QTableWidgetItem( reqRec.getDN() ));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightCertPolicyList()
{
    right_menu_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CERT_POLICY;

    QStringList headerList = { "Num", "Name", "Version", "NotBerfoer", "NotAfter", "Hash", "DNTemplate" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
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
    right_menu_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CRL_POLICY;

    QStringList headerList = { "Num", "Name", "Version", "LastUpdate", "NextUpdate", "Hash" };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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
    right_menu_->show();
    removeAllRight();
    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    right_type_ = RightType::TYPE_CERTIFICATE;

    QStringList headerList = { "Num", "RegTime", "KeyNum", "SignAlg", "IssuerNum", "SubjectDN" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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

    for( int i=0; i < certList.size(); i++ )
    {
        int pos = 0;
        CertRec cert = certList.at(i);
        char    sRegTime[64];

        QString strDNInfo;
        if( cert.isSelf() ) strDNInfo += "[Self]";
        if( cert.isCA() ) strDNInfo += "[CA]";
        strDNInfo += QString( "[%1] " ).arg( cert.getStatus() );
        strDNInfo += cert.getSubjectDN();

        JS_UTIL_getDateTime( cert.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getNum()) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( sRegTime ) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getKeyNum() )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( cert.getSignAlg() ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getIssuerNum() )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( strDNInfo ));
//        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg(cert.getCRLDP() )));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightCRLList( int nIssuerNum )
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_CRL;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;
    char sRegTime[64];

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = { "Num", "RegTime", "IssuerNum", "SignAlg", "CRLDP" };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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

    for( int i=0; i < crlList.size(); i++ )
    {
        CRLRec crl = crlList.at(i);

        JS_UTIL_getDateTime( crl.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crl.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sRegTime )));
        right_table_->setItem( i, 2, new QTableWidgetItem(QString("%1").arg(crl.getIssuerNum() )));
        right_table_->setItem( i, 3, new QTableWidgetItem( crl.getSignAlg() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( crl.getCRLDP() ));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightRevokeList(int nIssuerNum)
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_REVOKE;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = {"Num", "CertNum", "IssuerNum", "Serial", "RevokeDate", "Reason", "CRLDP" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg(revoke.getCRLDP())));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightUserList()
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_USER;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = {"Num", "RegTime", "Name", "SSN", "Email", "Status" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

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


    for( int i = 0; i < userList.size(); i++ )
    {
        char sRegTime[64];
        UserRec user = userList.at(i);
        right_table_->insertRow(i);

        JS_UTIL_getDateTime( user.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( user.getNum() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( user.getName())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( user.getSSN() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( user.getEmail() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( user.getStatus() )));
//        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg( user.getRefNum() )));
//        right_table_->setItem(i,7, new QTableWidgetItem(QString("%1").arg( user.getAuthCode() )));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightKMSList()
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_KMS;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = {"Seq", "RegTime", "Status", "Type", "ID", "Info" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<KMSRec> kmsList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getKMSSearchCount( strTarget, strWord );
        db_mgr_->getKMSList( strTarget, strWord, nOffset, nLimit, kmsList );
    }
    else
    {
        nTotalCount = db_mgr_->getKMSCount();
        db_mgr_->getKMSList( nOffset, nLimit, kmsList );
    }


    for( int i = 0; i < kmsList.size(); i++ )
    {
        char sRegTime[64];
        KMSRec kms = kmsList.at(i);
        right_table_->insertRow(i);

        JS_UTIL_getDateTime( kms.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( kms.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( kms.getStatus())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( kms.getType() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( kms.getID() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( kms.getInfo() )));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightSignerList(int nType)
{
    right_menu_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_SIGNER;

    QStringList headerList = { "Num", "RegTime", "Type", "DN", "Status", "Cert" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(5);
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<SignerRec> signerList;
    db_mgr_->getSignerList( nType, signerList );

    for( int i = 0; i < signerList.size(); i++ )
    {
        char sRegTime[64];
        SignerRec signer = signerList.at(i);
        right_table_->insertRow(i);

        JS_UTIL_getDateTime( signer.getRegTime(), sRegTime );
        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( signer.getNum() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( signer.getType() )));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( signer.getDN() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( signer.getStatus() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( signer.getCert() )));
    }
}

void MainWindow::createRightAuditList()
{
    right_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_AUDIT;

    int nTotalCount = 0;
    int nLimit = kListCount;
    int nPage = right_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = right_menu_->getCondName();
    QString strWord = right_menu_->getInputWord();

    QStringList headerList = {"Seq", "RegTime", "Kind", "Operation", "UserName", "Info", "MAC" };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<AuditRec> auditList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getAuditSearchCount( strTarget, strWord );
        db_mgr_->getAuditList( strTarget, strWord, nOffset, nLimit, auditList );
    }
    else
    {
        nTotalCount = db_mgr_->getAuditCount();
        db_mgr_->getAuditList( nOffset, nLimit, auditList );
    }


    for( int i = 0; i < auditList.size(); i++ )
    {
        char sRegTime[64];
        AuditRec audit = auditList.at(i);
        right_table_->insertRow(i);

        JS_UTIL_getDateTime( audit.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( audit.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( audit.getKind())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( audit.getOperation() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( audit.getUserName() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( audit.getInfo() )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg( audit.getMAC() )));
    }

    right_menu_->setTotalCount( nTotalCount );
    right_menu_->updatePageLabel();
}

void MainWindow::createRightStatistics()
{
    printf( "Set Statistics\n" );
    //stack_->addWidget( statistics_ );
    stack_->setCurrentIndex(1);
}

void MainWindow::showRightKeyPair( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;

    KeyPairRec keyPair;

    db_mgr_->getKeyPairRec( seq, keyPair );

    strMsg = "[ KeyPair information ]\n\n";
    strPart = QString( "Num:%1\n\n").arg( keyPair.getNum() );
    strMsg += strPart;

    strPart = QString( "Algorithm: %1\n\n").arg( keyPair.getAlg());
    strMsg += strPart;

    strPart = QString( "Name: %1\n\n").arg( keyPair.getName());
    strMsg += strPart;

    strPart = QString( "PublicKey: %1\n\n").arg( keyPair.getPublicKey());
    strMsg += strPart;

    strPart = QString( "PrivateKey: %1\n\n").arg( keyPair.getPrivateKey());
    strMsg += strPart;

    strPart = QString( "Param: %1\n\n").arg( keyPair.getParam());
    strMsg += strPart;

    strPart = QString( "Status: %1\n\n").arg( keyPair.getStatus());
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

    strMsg = "[ Request information ]\n\n";

    strPart = QString( "SEQ: %1\n\n").arg(reqRec.getSeq());
    strMsg += strPart;

    strPart = QString( "KeyNum: %1\n\n").arg(reqRec.getKeyNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n\n").arg( reqRec.getName() );
    strMsg += strPart;

    strPart = QString( "DN: %1\n\n").arg( reqRec.getDN());
    strMsg += strPart;

    strPart = QString( "Request: %1\n\n").arg( reqRec.getCSR() );
    strMsg += strPart;

    strPart = QString( "Hash: %1\n\n").arg( reqRec.getHash());
    strMsg += strPart;

    strPart = QString( "Status: %1\n\n").arg( reqRec.getStatus());
    strMsg += strPart;

    right_text_->setText(strMsg);
}

void MainWindow::showRightCertificate( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;
    char    sRegDate[64];

    CertRec certRec;
    db_mgr_->getCertRec( seq, certRec );

    strMsg = "[ Ceritificate information ]\n\n";

    strPart = QString("Num: %1\n\n").arg( certRec.getNum() );
    strMsg += strPart;

    JS_UTIL_getDateTime( certRec.getRegTime(), sRegDate );
    strPart = QString("RegDate: %1\n\n").arg( sRegDate );
    strMsg += strPart;

    strPart = QString( "KeyNum: %1\n\n").arg( certRec.getKeyNum() );
    strMsg += strPart;

    strPart = QString( "SignAlgorithm: %1\n\n").arg( certRec.getSignAlg() );
    strMsg += strPart;

    strPart = QString( "Certificate: %1\n\n").arg( certRec.getCert() );
    strMsg += strPart;

    strPart = QString( "IsCA: %1\n\n").arg( certRec.isCA() );
    strMsg += strPart;

    strPart = QString( "IsSelf: %1\n\n").arg( certRec.isSelf() );
    strMsg += strPart;

    strPart = QString( "SubjectDN: %1\n\n").arg( certRec.getSubjectDN() );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1\n\n").arg( certRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "Status: %1\n\n").arg( certRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "Serial: %1\n\n").arg( certRec.getSerial() );
    strMsg += strPart;

    strPart = QString( "DNHash: %1\n\n").arg( certRec.getDNHash() );
    strMsg += strPart;

    strPart = QString( "KeyHash: %1\n\n").arg( certRec.getKeyHash() );
    strMsg += strPart;

    strPart = QString( "CRLDP: %1\n\n").arg( certRec.getCRLDP() );
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

    strMsg = "[ Certificate policy information ]\n\n";

    strPart = QString( "Num: %1\n\n").arg( certPolicy.getNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n\n").arg( certPolicy.getName());
    strMsg += strPart;

    strPart = QString( "Version: %1\n\n").arg(certPolicy.getVersion());
    strMsg += strPart;

    strPart = QString( "NotBefore: %1\n\n").arg(certPolicy.getNotBefore());
    strMsg += strPart;

    strPart = QString( "NotAfter: %1\n\n").arg( certPolicy.getNotAfter());
    strMsg += strPart;

    strPart = QString( "Hash: %1\n\n").arg(certPolicy.getHash());
    strMsg += strPart;

    strPart = QString( "DNTemplate: %1\n\n").arg( certPolicy.getDNTemplate() );
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
    char    sRegTime[64];

    db_mgr_->getCRLRec( seq, crlRec );

    strMsg = "[ CRL information ]\n\n";

    strPart = QString( "Num: %1\n\n" ).arg( crlRec.getNum() );
    strMsg += strPart;

    JS_UTIL_getDateTime( crlRec.getRegTime(), sRegTime );
    strPart = QString( "RegTime: %1\n\n" ).arg( sRegTime );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1\n\n").arg( crlRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "SignAlgorithm: %1\n\n").arg(crlRec.getSignAlg());
    strMsg += strPart;

    strPart = QString( "CRLDP: %1\n\n").arg(crlRec.getCRLDP());
    strMsg += strPart;

    strPart = QString( "CRL: %1\n\n").arg( crlRec.getCRL());
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

    strMsg = "[ CRL information ]\n\n";

    strPart = QString( "Num: %1\n\n").arg(crlPolicy.getNum());
    strMsg += strPart;

    strPart = QString( "Name: %1\n\n").arg( crlPolicy.getName());
    strMsg += strPart;

    strPart = QString( "Version: %1\n\n").arg( crlPolicy.getVersion());
    strMsg += strPart;

    strPart = QString( "LastUpdate : %1\n\n").arg(crlPolicy.getLastUpdate());
    strMsg += strPart;

    strPart = QString("NextUpdate: %1\n\n").arg(crlPolicy.getNextUpdate());
    strMsg += strPart;

    strPart = QString("Hash: %1\n\n").arg(crlPolicy.getHash());
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

    strMsg = "[ Revoke information ]\n\n";

    strPart = QString( "Seq: %1\n\n").arg( revokeRec.getSeq());
    strMsg += strPart;

    strPart = QString( "CertNum: %1\n\n").arg( revokeRec.getCertNum() );
    strMsg += strPart;

    strPart = QString( "IssuerNum: %1\n\n").arg( revokeRec.getIssuerNum() );
    strMsg += strPart;

    strPart = QString( "Serial: %1\n\n").arg( revokeRec.getSerial() );
    strMsg += strPart;

    strPart = QString( "RevokeDate: %1\n\n").arg( revokeRec.getRevokeDate());
    strMsg += strPart;

    strPart = QString( "Reason: %1\n\n").arg( revokeRec.getReason() );
    strMsg += strPart;

    strPart = QString( "CRLDP: %1\n\n").arg( revokeRec.getCRLDP() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightUser( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;
    char sRegTime[64];

    UserRec userRec;
    db_mgr_->getUserRec( seq, userRec );

    strMsg = "[ User information ]\n\n";

    strPart = QString( "Num: %1\n").arg( userRec.getNum());
    strMsg += strPart;

    JS_UTIL_getDateTime( userRec.getRegTime(), sRegTime );
    strPart = QString( "RegTime: %1\n\n").arg( sRegTime );
    strMsg += strPart;

    strPart = QString( "Name: %1\n\n").arg( userRec.getName() );
    strMsg += strPart;

    strPart = QString( "SSN: %1\n\n").arg( userRec.getSSN() );
    strMsg += strPart;

    strPart = QString( "Email: %1\n\n").arg( userRec.getEmail() );
    strMsg += strPart;

    strPart = QString( "Status: %1\n\n").arg( userRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "RefNum: %1\n\n").arg( userRec.getRefNum() );
    strMsg += strPart;

    strPart = QString( "AuthCode: %1\n\n").arg( userRec.getAuthCode() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightKMS( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;
    char sRegTime[64];

    KMSRec kmsRec;
    db_mgr_->getKMSRec( seq, kmsRec );

    strMsg = "[ KMS information ]\n\n";

    strPart = QString( "Seq: %1\n").arg( kmsRec.getSeq());
    strMsg += strPart;

    JS_UTIL_getDateTime( kmsRec.getRegTime(), sRegTime );
    strPart = QString( "RegTime: %1\n\n").arg( sRegTime );
    strMsg += strPart;

    strPart = QString( "Status: %1\n\n").arg( kmsRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "Type: %1\n\n").arg( kmsRec.getType() );
    strMsg += strPart;

    strPart = QString( "ID: %1\n\n").arg( kmsRec.getID() );
    strMsg += strPart;

    strPart = QString( "Info: %1\n\n").arg( kmsRec.getInfo() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightAudit( int seq )
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;
    char sRegTime[64];

    AuditRec auditRec;
    db_mgr_->getAuditRec( seq, auditRec );

    strMsg = "[ Audit information ]\n\n";

    strPart = QString( "Seq: %1\n").arg( auditRec.getSeq());
    strMsg += strPart;

    JS_UTIL_getDateTime( auditRec.getRegTime(), sRegTime );
    strPart = QString( "RegTime: %1\n\n").arg( sRegTime );
    strMsg += strPart;

    strPart = QString( "Kind: %1\n\n").arg( auditRec.getKind() );
    strMsg += strPart;

    strPart = QString( "Operation: %1\n\n").arg( auditRec.getOperation() );
    strMsg += strPart;

    strPart = QString( "UserName: %1\n\n").arg( auditRec.getUserName() );
    strMsg += strPart;

    strPart = QString( "Info: %1\n\n").arg( auditRec.getInfo() );
    strMsg += strPart;

    strPart = QString( "MAC: %1\n\n").arg( auditRec.getMAC() );
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightSigner(int seq)
{
    if( db_mgr_ == NULL ) return;

    QString strMsg;
    QString strPart;
    char    sRegTime[64];

    SignerRec signerRec;
    db_mgr_->getSignerRec( seq, signerRec );

    strMsg = "[ Signer information ]\n\n";

    strPart = QString( "Num: %1\n\n").arg( signerRec.getNum());
    strMsg += strPart;

    JS_UTIL_getDateTime( signerRec.getRegTime(), sRegTime );
    strPart = QString( "RegTime: %1\n\n").arg( sRegTime );
    strMsg += strPart;

    strPart = QString( "Type: %1\n\n").arg( signerRec.getType() );
    strMsg += strPart;

    strPart = QString( "DN: %1\n\n").arg( signerRec.getDN() );
    strMsg += strPart;

    strPart = QString( "DNHash: %1\n\n").arg( signerRec.getDNHash() );
    strMsg += strPart;

    strPart = QString( "Cert: %1\n\n").arg( signerRec.getCert() );
    strMsg += strPart;

    strPart = QString( "Status: %1\n\n").arg( signerRec.getStatus() );
    strMsg += strPart;

    strPart = QString( "Desc: %1\n\n").arg( signerRec.getDesc());
    strMsg += strPart;

    right_text_->setText( strMsg );
}

void MainWindow::showRightStatistics()
{
//    stack_->addWidget( statistics_ );
}

int MainWindow::rightCount()
{
    return right_table_->rowCount();
}
