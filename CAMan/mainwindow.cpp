#include <QFileDialog>
#include <QtWidgets>

#include "js_util.h"
#include "js_gen.h"
#include "js_ocsp.h"
#include "js_http.h"
#include "js_cmp.h"
#include "js_json.h"
#include "js_pkcs7.h"
#include "js_scep.h"

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
#include "make_cert_profile_dlg.h"
#include "make_crl_dlg.h"
#include "make_crl_profile_dlg.h"
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
#include "kms_attrib_rec.h"
#include "cert_profile_rec.h"
#include "crl_profile_rec.h"
#include "crl_rec.h"
#include "profile_ext_rec.h"
#include "revoke_rec.h"
#include "user_rec.h"
#include "user_dlg.h"
#include "signer_dlg.h"
#include "signer_rec.h"
#include "server_status_dlg.h"
#include "man_tray_icon.h"
#include "stat_form.h"
#include "audit_rec.h"
#include "tsp_dlg.h"
#include "tsp_rec.h"
#include "server_status_service.h"
#include "tst_info_dlg.h"
#include "admin_rec.h"
#include "admin_dlg.h"

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
    delete log_text_;
    delete right_table_;
    delete search_menu_;
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
    log_text_ = new QTextEdit();
    right_table_ = new QTableWidget;
    left_model_ = new ManTreeModel(this);
    search_menu_ = new SearchMenu;
    search_menu_->setMaximumHeight( 20 );

    left_tree_->setModel(left_model_);

    log_text_->setFont( QFont("굴림체") );
    log_text_->setReadOnly(true);

    right_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QWidget *rightWidget = new QWidget;

    stack_ = new QStackedLayout();
    stat_ = new StatForm;

    stack_->addWidget( vsplitter_ );
    stack_->addWidget( stat_ );
    rightWidget->setLayout(stack_);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget( rightWidget );

    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget(search_menu_);
    vsplitter_->addWidget(log_text_);

    QList <int> vsizes;
    vsizes << 760 << 10 << 600;
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

    const QIcon newKeyIcon = QIcon::fromTheme("new-key", QIcon(":/images/key_reg.png"));
    QAction *newKeyAct = new QAction( newKeyIcon, tr("&NewKey"), this );
    newKeyAct->setStatusTip(tr("Generate new key pair"));
    connect( newKeyAct, &QAction::triggered, this, &MainWindow::newKey );
    toolsMenu->addAction( newKeyAct );
    toolsToolBar->addAction( newKeyAct );

    const QIcon csrIcon = QIcon::fromTheme("certificate-request", QIcon(":/images/csr.png"));
    QAction *makeReqAct = new QAction( csrIcon, tr("Make&Request"), this );
    makeReqAct->setStatusTip(tr( "Make Request"));
    connect( makeReqAct, &QAction::triggered, this, &MainWindow::makeRequest );
    toolsMenu->addAction( makeReqAct );
    toolsToolBar->addAction( makeReqAct );

    if( manApplet->isPRO() )
    {
        const QIcon userRegIcon = QIcon::fromTheme("user-register", QIcon(":/images/user_reg.png"));
        QAction *regUserAct = new QAction( userRegIcon, tr("Register&User"), this );
        regUserAct->setStatusTip(tr( "Register User"));
        connect( regUserAct, &QAction::triggered, this, &MainWindow::registerUser );
        toolsMenu->addAction( regUserAct );
        toolsToolBar->addAction( regUserAct );

        const QIcon signerRegIcon = QIcon::fromTheme("signer-register", QIcon(":/images/signer_reg.png"));
        QAction *regSignerAct = new QAction( signerRegIcon, tr("Register&Signer"), this );
        regSignerAct->setStatusTip(tr( "Register Signer"));
        connect( regSignerAct, &QAction::triggered, this, &MainWindow::registerREGSigner );
        toolsMenu->addAction( regSignerAct );
        toolsToolBar->addAction( regSignerAct );
    }

    const QIcon certProfileIcon = QIcon::fromTheme("cert-profile", QIcon(":/images/cert_profile.png"));
    QAction *makeCertProfileAct = new QAction( certProfileIcon, tr("MakeCert&Profile"), this );
    makeCertProfileAct->setStatusTip(tr( "Make certificate profile"));
    connect( makeCertProfileAct, &QAction::triggered, this, &MainWindow::makeCertProfile );
    toolsMenu->addAction( makeCertProfileAct );
    toolsToolBar->addAction( makeCertProfileAct );

    const QIcon crlProfileIcon = QIcon::fromTheme("crl-profile", QIcon(":/images/crl_profile.png"));
    QAction *makeCRLProfileAct = new QAction( crlProfileIcon, tr("MakeC&RLProfile"), this );
    connect( makeCRLProfileAct, &QAction::triggered, this, &MainWindow::makeCRLProfile);
    toolsMenu->addAction( makeCRLProfileAct );
    toolsToolBar->addAction( makeCRLProfileAct );
    makeCRLProfileAct->setStatusTip(tr( "Make CRL Profile"));

    const QIcon certIcon = QIcon::fromTheme("make-certificate", QIcon(":/images/cert.png"));
    QAction* makeCertAct = new QAction( certIcon, tr("Make&Certificate"), this );
    connect( makeCertAct, &QAction::triggered, this, &MainWindow::makeCertificate );
    toolsMenu->addAction( makeCertAct );
    toolsToolBar->addAction( makeCertAct );
    makeCertAct->setStatusTip(tr("Make certificate"));


    const QIcon crlIcon = QIcon::fromTheme("make-crl", QIcon(":/images/crl.png"));
    QAction* makeCRLAct = new QAction( crlIcon, tr("MakeCR&L"), this );
    connect( makeCRLAct, &QAction::triggered, this, &MainWindow::makeCRL );
    toolsMenu->addAction( makeCRLAct );
    toolsToolBar->addAction( makeCRLAct );
    makeCRLAct->setStatusTip(tr("Make CRL"));

    const QIcon revokeIcon = QIcon::fromTheme("revoke-certificate", QIcon(":/images/revoke.png"));
    QAction* revokeCertAct = new QAction( revokeIcon, tr("Revo&keCert"), this );
    connect( revokeCertAct, &QAction::triggered, this, &MainWindow::revokeCertificate );
    toolsMenu->addAction( revokeCertAct );
    toolsToolBar->addAction( revokeCertAct );
    revokeCertAct->setStatusTip(tr("Revoke certificate"));

    QMenu *dataMenu = menuBar()->addMenu(tr("&Data"));
    QToolBar *dataToolBar = addToolBar(tr("Data"));

    const QIcon diskIcon = QIcon::fromTheme("disk", QIcon(":/images/disk.png"));
    QAction* importDataAct = new QAction( diskIcon, tr("&ImportData"), this );
    connect( importDataAct, &QAction::triggered, this, &MainWindow::importData );
    dataMenu->addAction( importDataAct );
    dataToolBar->addAction( importDataAct );
    importDataAct->setStatusTip(tr("Import data"));

    const QIcon pubLDAPIcon = QIcon::fromTheme("Publish-LDAP", QIcon(":/images/pub_ldap.png"));
    QAction *pubLDAPAct = new QAction( pubLDAPIcon, tr("&PublishLDAP"), this);
    connect( pubLDAPAct, &QAction::triggered, this, &MainWindow::publishLDAP);
    pubLDAPAct->setStatusTip(tr("Publish LDAP"));
    dataMenu->addAction( pubLDAPAct );
    dataToolBar->addAction( pubLDAPAct );

    const QIcon getLDAPIcon = QIcon::fromTheme("Get-LDAP", QIcon(":/images/get_ldap.png"));
    QAction *getLDAPAct = new QAction( getLDAPIcon, tr("&GetLDAP"), this);
    connect( getLDAPAct, &QAction::triggered, this, &MainWindow::getLDAP);
    getLDAPAct->setStatusTip(tr("Get LDAP"));
    dataMenu->addAction( getLDAPAct );
    dataToolBar->addAction( getLDAPAct );


    const QIcon timeIcon = QIcon::fromTheme("Timestamp", QIcon(":/images/timestamp.png"));
    QAction *tspAct = new QAction( timeIcon, tr("&TSP"), this);
    connect( tspAct, &QAction::triggered, this, &MainWindow::tsp);
    tspAct->setStatusTip(tr("TimeStampProtocol Service"));
    dataMenu->addAction( tspAct );
    dataToolBar->addAction( tspAct );


    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

    if( manApplet->isPRO() )
    {
        const QIcon statusIcon = QIcon::fromTheme("server-status", QIcon(":/images/server_status.png"));
        QAction *srvStatusAct = new QAction( statusIcon, tr("ServerS&tatus"), this);
        connect( srvStatusAct, &QAction::triggered, this, &MainWindow::serverStatus);
        srvStatusAct->setStatusTip(tr("Server Status Information"));
        helpMenu->addAction( srvStatusAct );
        helpToolBar->addAction( srvStatusAct );
    }


    const QIcon settingIcon = QIcon::fromTheme("setting", QIcon(":/images/setting.png"));
    QAction *settingsAct = new QAction( settingIcon, tr("&Settings"), this);
    connect( settingsAct, &QAction::triggered, this, &MainWindow::settings);
    settingsAct->setStatusTip(tr("Settings CAMan"));
    helpMenu->addAction( settingsAct );
    helpToolBar->addAction( settingsAct );

    const QIcon caManIcon = QIcon::fromTheme("caman", QIcon(":/images/caman.png"));
    QAction *aboutAct = new QAction( caManIcon, tr("&About CAMan"), this);
    connect( aboutAct, &QAction::triggered, this, &MainWindow::about);
    helpMenu->addAction( aboutAct );
    helpToolBar->addAction( aboutAct );
    aboutAct->setStatusTip(tr("About CAMan"));

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
    log_text_->setText("");

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
        menu.addAction( tr( "Export PFX"), this, &MainWindow::exportPFX );
        menu.addAction( tr( "View Certificate"), this, &MainWindow::viewCertificate );
        menu.addAction( tr("Delete Certificate" ), this, &MainWindow::deleteCertificate );
        menu.addAction( tr("Revoke Certificate"), this, &MainWindow::revokeCertificate );
        menu.addAction( tr( "Publish Certificate" ), this, &MainWindow::publishLDAP );
        menu.addAction( tr("Status Certificate"), this, &MainWindow::certStatus );

        if( manApplet->isPRO() )
        {
            menu.addAction( tr("Check OCSP"), this, &MainWindow::checkOCSP );
            menu.addAction( tr("UpdateCMP"), this, &MainWindow::updateCMP );
            menu.addAction( tr("RevokeCMP"), this, &MainWindow::revokeCMP );
            menu.addAction( tr("StatusByReg"), this, &MainWindow::statusByReg );
            menu.addAction( tr("RevokeByReg"), this, &MainWindow::revokeByReg );
            menu.addAction( tr( "RenewSCEP" ), this, &MainWindow::renewSCEP );
            menu.addAction( tr( "getCRLSCEP"), this, &MainWindow::getCRLSCEP );
        }
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

        if( manApplet->isPRO() )
        {
            menu.addAction(tr("Issue SCEP"), this, &MainWindow::issueSCEP );
        }
    }
    else if( right_type_ == RightType::TYPE_CERT_PROFILE )
    {
        menu.addAction(tr("Delete CertProfile"), this, &MainWindow::deleteCertProfile );
        menu.addAction(tr("Edit CertProfile" ), this, &MainWindow::editCertProfile );
    }
    else if( right_type_ == RightType::TYPE_CRL_PROFILE )
    {
        menu.addAction(tr("Delete CRLProfile"), this, &MainWindow::deleteCRLProfile );
        menu.addAction(tr("Edit CRLProfile"), this, &MainWindow::editCRLProfile );
    }
    else if( right_type_ == RightType::TYPE_ADMIN )
    {
        menu.addAction(tr("Edit Admin"), this, &MainWindow::editAdmin );
    }
    else if( right_type_ == RightType::TYPE_USER )
    {
        menu.addAction(tr("Delete User"), this, &MainWindow::deleteUser );

        if( manApplet->isPRO() )
        {
            menu.addAction(tr("Issue CMP"), this, &MainWindow::issueCMP );
        }
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        menu.addAction(tr("Delete Signer"), this, &MainWindow::deleteSigner );
    }
    else if( right_type_ == RightType::TYPE_KMS )
    {
        menu.addAction(tr("Activate Key"), this, &MainWindow::activateKey );
        menu.addAction(tr("Delete Key"), this, &MainWindow::deleteKey );
    }
    else if( right_type_ == RightType::TYPE_AUDIT )
    {
        menu.addAction(tr("Verify Audit"), this, &MainWindow::verifyAudit );
    }
    else if( right_type_ == RightType::TYPE_TSP )
    {
        menu.addAction(tr("View TSTInfo"), this, &MainWindow::viewTSTInfo );
        menu.addAction(tr("VerifyTSMessage"), this, &MainWindow::verifyTSMessage );
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
    pKeyPairItem->setIcon(QIcon(":/images/key_reg.png"));
    pKeyPairItem->setType( CM_ITEM_TYPE_KEYPAIR );
    pTopItem->appendRow( pKeyPairItem );

    ManTreeItem *pCSRItem = new ManTreeItem( QString("Request"));
    pCSRItem->setIcon(QIcon(":/images/csr.jpg"));
    pCSRItem->setType( CM_ITEM_TYPE_REQUEST );
    pTopItem->appendRow( pCSRItem );

    if( manApplet->isPRO() )
    {
        ManTreeItem *pAdminItem = new ManTreeItem( QString("Admin") );
        pAdminItem->setIcon(QIcon(":/images/admin.png"));
        pAdminItem->setType( CM_ITEM_TYPE_ADMIN );
        pTopItem->appendRow( pAdminItem );

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
    }


    ManTreeItem *pCertProfileItem = new ManTreeItem( QString("CertProfile" ) );
    pCertProfileItem->setIcon(QIcon(":/images/cert_profile.png"));
    pCertProfileItem->setType( CM_ITEM_TYPE_CERT_PROFILE );
    pTopItem->appendRow( pCertProfileItem );

    ManTreeItem *pCRLProfileItem = new ManTreeItem( QString("CRLProfile" ) );
    pCRLProfileItem->setIcon(QIcon(":/images/crl_profile.png"));
    pCRLProfileItem->setType( CM_ITEM_TYPE_CRL_PROFILE );
    pTopItem->appendRow( pCRLProfileItem );

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

    if( manApplet->isPRO() )
    {
        ManTreeItem *pKMSItem = new ManTreeItem( QString( "KMS" ));
        pKMSItem->setIcon(QIcon(":/images/kms.png"));
        pKMSItem->setType( CM_ITEM_TYPE_KMS );
        pTopItem->appendRow( pKMSItem );

        ManTreeItem *pTSPItem = new ManTreeItem( QString( "TSP" ));
        pTSPItem->setIcon(QIcon(":/images/timestamp.png"));
        pTSPItem->setType( CM_ITEM_TYPE_TSP );
        pTopItem->appendRow( pTSPItem );
    }

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


    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_DB, strPath );

    if( fileName.length() < 1 )
    {
        return;
    }

    JS_BIN_set( &binDB, (unsigned char *)data.data(), data.size() );
    JS_BIN_fileWrite( &binDB, fileName.toLocal8Bit().toStdString().c_str() );
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
        QString strippedName = QString( "%1 ").arg(i);
        strippedName += QFileInfo(recentFilePaths.at(i)).fileName();

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

    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_DB, strPath );
    if( fileName.length() < 1 ) return;

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

void MainWindow::makeCertProfile()
{
    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.setEdit(false);
    makeCertProfileDlg.setProfileNum(-1);

    makeCertProfileDlg.exec();
}

void MainWindow::makeCRLProfile()
{
    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.setEdit(false);
    makeCRLProfileDlg.setProfileNum(-1);
    makeCRLProfileDlg.exec();
}

void MainWindow::editCertProfile()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.setEdit(true);
    makeCertProfileDlg.setProfileNum(num);

    makeCertProfileDlg.exec();
}

void MainWindow::editCRLProfile()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.setEdit(true);
    makeCRLProfileDlg.setProfileNum(num);
    makeCRLProfileDlg.exec();
}

void MainWindow::makeCertificate()
{
    ManTreeItem *pItem = currentItem();

    MakeCertDlg makeCertDlg;

    if( pItem )
    {
        if( pItem->getType() == CM_ITEM_TYPE_CA || pItem->getType() == CM_ITEM_TYPE_SUBCA || pItem->getType() == CM_ITEM_TYPE_ROOTCA )
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
        if( pItem->getType() == CM_ITEM_TYPE_CA || pItem->getType() == CM_ITEM_TYPE_SUBCA || pItem->getType() == CM_ITEM_TYPE_ROOTCA )
        {
            makeCRLDlg.setFixIssuer( pItem->text() );
        }
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

void MainWindow::registerREGSigner()
{
    SignerDlg signerDlg;
    signerDlg.setType( SIGNER_TYPE_REG );
    signerDlg.exec();
}

void MainWindow::registerOCSPSigner()
{
    SignerDlg signerDlg;
    signerDlg.setType( SIGNER_TYPE_OCSP );
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
    AboutDlg aboutDlg;
    aboutDlg.exec();
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

void MainWindow::deleteCertProfile()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    db_mgr_->delCertProfile( num );
    db_mgr_->delCertProfileExtensionList( num );
    createRightCertProfileList();
}

void MainWindow::deleteCRLProfile()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    db_mgr_->delCRLProfile( num );
    db_mgr_->delCRLProfileExtensionList( num );
    createRightCRLProfileList();
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

void MainWindow::registerAdmin()
{
    AdminDlg adminDlg;
    adminDlg.exec();
}

void MainWindow::editAdmin()
{
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    AdminDlg adminDlg;
    adminDlg.setEditMode(true);
    adminDlg.setSeq( num );
    adminDlg.exec();
}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}

void MainWindow::log( const QString strLog, QColor cr )
{
    QTextCursor cursor = log_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );

    log_text_->setTextCursor( cursor );
    log_text_->repaint();
}

void MainWindow::logClear()
{
    log_text_->clear();
}

void MainWindow::logCurorTop()
{
    log_text_->moveCursor(QTextCursor::Start);
}

void MainWindow::treeMenuClick(QModelIndex index )
{
    int nType = -1;
    int nNum = -1;

    ManTreeItem *pItem = (ManTreeItem *)left_model_->itemFromIndex(index);

    if( pItem == NULL ) return;

    nNum = pItem->getDataNum();
    nType = pItem->getType();

    printf( "Num: %d, Type : %d\n", nNum, nType );
    fflush( stdout );

    search_menu_->setCurPage(0);
    search_menu_->setLeftNum( nNum );
    search_menu_->setLeftType( nType );

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

    QTableWidgetItem* item = right_table_->item(row, 0);
    int nSeq = item->text().toInt();

    if( right_type_ == RightType::TYPE_KEYPAIR )
    {
        logKeyPair( nSeq );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        logRequest( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CERTIFICATE )
    {
        logCertificate( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        logCRL( nSeq );
    }
    else if( right_type_ == RightType::TYPE_REVOKE )
    {
        logRevoke( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CERT_PROFILE )
    {
        logCertProfile( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CRL_PROFILE )
    {
        logCRLProfile( nSeq );
    }
    else if( right_type_ == RightType::TYPE_USER )
    {
        logUser( nSeq );
    }
    else if( right_type_ == RightType::TYPE_ADMIN )
    {
        logAdmin( nSeq );
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        logSigner( nSeq );
    }
    else if( right_type_ == RightType::TYPE_KMS )
    {
        logKMS( nSeq );
    }
    else if( right_type_ == RightType::TYPE_STATISTICS )
    {
        logStatistics();
    }
    else if( right_type_ == RightType::TYPE_AUDIT )
    {
        logAudit( nSeq );
    }
    else if( right_type_ == RightType::TYPE_TSP )
    {
        logTSP( nSeq );
    }
}

void MainWindow::activateKey()
{
    int ret = 0;
    SSL_CTX     *pCTX = NULL;
    SSL         *pSSL = NULL;
    Authentication  *pAuth = NULL;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    char sUUID[64];
    char *pUUID = NULL;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    sprintf( sUUID, "%d", num );

    ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    JS_KMS_encodeActivateReq( pAuth, sUUID, &binReq );
    JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    JS_KMS_decodeActivateRsp( &binRsp, &pUUID );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    if( pUUID ) JS_free( pUUID );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth ) JS_KMS_resetAuthentication( pAuth );

    if( ret != 0 )
        manApplet->warningBox( tr("Fail to activate key" ), this );
    else
    {
        manApplet->messageBox( tr( "success to activate key" ), this );
        createRightKMSList();
    }

}

void MainWindow::registerKey()
{
    ImportDlg importDlg;
    importDlg.setType(0);
    importDlg.setKMIPCheck();
    importDlg.exec();
}

void MainWindow::deleteKey()
{
    int ret = 0;
    SSL_CTX     *pCTX = NULL;
    SSL         *pSSL = NULL;
    Authentication  *pAuth = NULL;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    char sUUID[64];


    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    sprintf( sUUID, "%d", num );

    ret = getKMIPConnection( manApplet->settingsMgr(), &pCTX, &pSSL, &pAuth );
    if( ret != 0 )
    {
        ret = -1;
        goto end;
    }

    JS_KMS_encodeDestroyReq( pAuth, sUUID, &binReq );
    JS_KMS_sendReceive( pSSL, &binReq, &binRsp );
    JS_KMS_decodeDestroyRsp( &binRsp );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth ) JS_KMS_resetAuthentication( pAuth );

    if( ret != 0 )
        manApplet->warningBox( tr("Fail to delete key" ), this );
    else
    {
        manApplet->messageBox( tr( "success to delete key" ), this );
        createRightKMSList();
    }
}

void MainWindow::issueCMP()
{
    int ret = 0;
    BINList *pTrustList = NULL;
    BIN binRefNum = {0,0};
    BIN binAuthCode = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    BIN binCert = {0,0};
    JNameValList    *pInfoList = NULL;


    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

   if( manApplet->settingsMgr()->CMPUse() == false )
   {
       manApplet->warningBox( tr( "CMPServer is not set" ), this );
       return;
   }

   CMPSetTrustList( manApplet->settingsMgr(), &pTrustList );
   UserRec userRec;
   db_mgr_->getUserRec( num, userRec );

   JS_BIN_set( &binRefNum, (unsigned char *)userRec.getRefNum().toStdString().c_str(), userRec.getRefNum().length() );
   JS_BIN_set( &binAuthCode, (unsigned char *)userRec.getAuthCode().toStdString().c_str(), userRec.getAuthCode().length() );

   QString strURL = manApplet->settingsMgr()->CMPURI();
   strURL += "/CMP";

   QString strDN = "CN=";
   strDN += userRec.getName();
   strDN += manApplet->settingsMgr()->baseDN();

   ret = JS_CMP_clientIssueGENM( strURL.toStdString().c_str(), pTrustList, &binRefNum, &binAuthCode, &pInfoList );
   if( ret != 0 ) goto end;

   ret = JS_PKI_RSAGenKeyPair( 2048, 65537, &binPub, &binPri );
   if( ret != 0 ) goto end;

   writeKeyPairDB( db_mgr_, userRec.getName().toStdString().c_str(), &binPub, &binPri  );

   ret = JS_CMP_clientIR( strURL.toStdString().c_str(), pTrustList, strDN.toStdString().c_str(), &binRefNum, &binAuthCode, &binPri, &binCert );
   if( ret != 0 ) goto end;

   writeCertDB( db_mgr_, &binCert );

   ret = JS_CMP_clientIssueCertConf( strURL.toStdString().c_str(), pTrustList, &binRefNum, &binAuthCode );
   if( ret != 0 ) goto end;

end:

   if( ret == 0 )
   {
       manApplet->messageBox( tr("CMP Issue OK" ), this );
   }
   else
   {
       manApplet->warningBox( tr( "CMP Issue Fail" ), this );
   }

   JS_BIN_reset( &binRefNum );
   JS_BIN_reset( &binAuthCode );
   JS_BIN_reset( &binPri );
   JS_BIN_reset( &binPub );
   JS_BIN_reset( &binCert );
   if( pTrustList ) JS_BIN_resetList( &pTrustList );
   if( pInfoList ) JS_UTIL_resetNameValList( &pInfoList );
}

void MainWindow::updateCMP()
{
    int ret = 0;
    BINList *pTrustList = NULL;
    JNameValList    *pInfoList = NULL;

    BIN binCert = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    BIN binNewCert = {0,0};
    BIN binNewPri = {0,0};
    BIN binCACert = {0,0};

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

   if( manApplet->settingsMgr()->CMPUse() == false )
   {
       manApplet->warningBox( tr( "CMPServer is not set" ), this );
       return;
   }

   CMPSetTrustList( manApplet->settingsMgr(), &pTrustList );
   CertRec certRec;
   db_mgr_->getCertRec( num, certRec );

   if( certRec.getKeyNum() <= 0 )
   {
       manApplet->warningBox( tr("KeyPair information is not set"), this );
       return;
   }

   KeyPairRec keyPair;
   db_mgr_->getKeyPairRec( certRec.getKeyNum(), keyPair );

   JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
   JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

   QString strURL = manApplet->settingsMgr()->CMPURI();
   strURL += "/CMP";
   QString strCAPath = manApplet->settingsMgr()->CMPCACertPath();

   JS_BIN_fileRead( strCAPath.toLocal8Bit().toStdString().c_str(), &binCACert );

   ret = JS_CMP_clientUpdateGENM( strURL.toStdString().c_str(), pTrustList, &binCert, &binPri, &pInfoList );
   if( ret != 0 ) goto end;

   ret = JS_PKI_RSAGenKeyPair( 2048, 65537, &binPub, &binNewPri );
   if( ret != 0 ) goto end;

   writeKeyPairDB( db_mgr_, certRec.getSubjectDN().toStdString().c_str(), &binPub, &binNewPri );

   ret = JS_CMP_clientKUR( strURL.toStdString().c_str(), pTrustList, &binCACert, &binCert, &binPri, &binNewPri, &binNewCert );
   if( ret != 0 ) goto end;

   writeCertDB( db_mgr_, &binNewCert );

   ret = JS_CMP_clientUpdateCertConf( strURL.toStdString().c_str(), pTrustList, &binNewCert, &binNewPri );
   if( ret != 0 ) goto end;

end :
   if( ret == 0 )
   {
       manApplet->messageBox( tr("CMP Update OK" ), this );
       manApplet->mainWindow()->createRightCertList( certRec.getIssuerNum() );
   }
   else
   {
       manApplet->warningBox( tr( "CMP Update Fail" ), this );
   }

   JS_BIN_reset( &binPri );
   JS_BIN_reset( &binCert );
   JS_BIN_reset( &binPub );
   JS_BIN_reset( &binCACert );
   JS_BIN_reset( &binNewPri );
   JS_BIN_reset( &binNewCert );
   if( pTrustList ) JS_BIN_resetList( &pTrustList );
   if( pInfoList ) JS_UTIL_resetNameValList( &pInfoList );
}

void MainWindow::revokeCMP()
{
    int ret = 0;
    BINList *pTrustList = NULL;
    BIN binCert = {0,0};
    BIN binPri = {0,0};
    BIN binCACert = {0,0};
    BIN binResCert = {0,0};
    int nReason = 0;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

   if( manApplet->settingsMgr()->CMPUse() == false )
   {
       manApplet->warningBox( tr( "CMPServer is not set" ), this );
       return;
   }

   CMPSetTrustList( manApplet->settingsMgr(), &pTrustList );
   CertRec certRec;
   db_mgr_->getCertRec( num, certRec );
   KeyPairRec keyPair;

   if( certRec.getKeyNum() <= 0 )
   {
       manApplet->warningBox(tr("KeyPair information is not set"), this );
       return;
   }

   db_mgr_->getKeyPairRec( certRec.getKeyNum(), keyPair );

   JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
   JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

   QString strURL = manApplet->settingsMgr()->CMPURI();
   strURL += "/CMP";
   QString strCAPath = manApplet->settingsMgr()->CMPCACertPath();

   JS_BIN_fileRead( strCAPath.toLocal8Bit().toStdString().c_str(), &binCACert );

   ret = JS_CMP_clientRR( strURL.toStdString().c_str(), pTrustList, &binCACert, &binCert, &binPri, nReason, &binResCert );

   if( ret == 0 )
   {
       manApplet->messageBox( tr("CMP Revoke OK" ), this );
       manApplet->mainWindow()->createRightCertList( certRec.getIssuerNum() );
   }
   else
   {
       manApplet->warningBox( tr( "CMP Revoke Fail" ), this );
   }

   JS_BIN_reset( &binPri );
   JS_BIN_reset( &binCert );
   JS_BIN_reset( &binResCert );
   JS_BIN_reset( &binCACert );

   if( pTrustList ) JS_BIN_resetList( &pTrustList );
}

void MainWindow::verifyAudit()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    AuditRec audit;

    dbMgr()->getAuditRec( num, audit );

    ret = verifyAuditRec( audit );
    if( ret == 0 )
        manApplet->messageBox( tr( "MAC Verify OK" ), this );
    else
        manApplet->warningBox( tr( "MAC is not valid" ), this );
}

void MainWindow::viewTSTInfo()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    TSTInfoDlg tstInfoDlg;
    tstInfoDlg.setSeq( num );
    tstInfoDlg.exec();
}

void MainWindow::verifyTSMessage()
{
    int ret = 0;
    BIN binTS = {0,0};
    BIN binCert = {0,0};
    BIN binData = {0,0};

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    TSPRec tspRec;
    db_mgr_->getTSPRec( num, tspRec );
    JS_BIN_decodeHex( tspRec.getData().toStdString().c_str(), &binTS );


    SettingsMgr *smgr = manApplet->settingsMgr();
    if( smgr )
    {
        if( smgr->TSPUse() )
        {
            JS_BIN_fileRead( smgr->TSPSrvCertPath().toStdString().c_str(), &binCert );
        }
    }

    ret = JS_PKCS7_verifySignedData( &binTS, &binCert, &binData );
    QString strVerify = QString( "Verify val:%1" ).arg( ret );

    manApplet->messageBox( strVerify );

    JS_BIN_reset( &binTS );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binData );
}

void MainWindow::issueSCEP()
{
    int nRet = 0;
    int nStatus = 0;
    BIN binSSLPri = {0,0};
    BIN binSSLCert = {0,0};
    BIN binCACert = {0,0};
    BIN binCSR = {0,0};
    BIN binPri = {0,0};
    BIN binSenderNonce = {0,0};
    char *pTransID = NULL;
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binSignedData = {0,0};
    BIN binNewCert = {0,0};
    char *pHex = NULL;

    SettingsMgr *smgr = manApplet->settingsMgr();

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    ReqRec req;
    db_mgr_->getReqRec( num, req );
    KeyPairRec keyPair;
    db_mgr_->getKeyPairRec( req.getKeyNum(), keyPair );

    if( smgr->SCEPURI() == false ) return;

    QString strSCEPURL = smgr->SCEPURI();
    QString strURL;

    if( smgr->SCEPMutualAuth() )
    {
        QString strCertPath = smgr->SCEPCertPath();
        QString strPriPath = smgr->SCEPPriKeyPath();

        JS_BIN_fileRead( strCertPath.toLocal8Bit().toStdString().c_str(), &binSSLCert );
        JS_BIN_fileRead( strPriPath.toLocal8Bit().toStdString().c_str(), &binSSLPri );
    }

    JS_PKI_genRandom( 16, &binSenderNonce );
    JS_SCEP_makeTransID( &binCSR, &pTransID );

    strURL = QString( "%1?operation=GetCACert" ).arg( strSCEPURL );

    nRet = JS_HTTP_requestGetBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                &nStatus,
                &binCACert );

    if( nRet != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        fprintf( stderr, "fail to request Get [%d:%d]\n", nRet, nStatus );
        manApplet->warningBox( "fail to request Get", this );
        goto end;
    }

    JS_BIN_decodeHex( req.getCSR().toStdString().c_str(), &binCSR );
    JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

    nRet = JS_SCEP_makePKIReq(
                &binCSR,
                &binPri,
                NULL,
                &binCACert,
                &binSenderNonce,
                pTransID,
                &binReq );

    if( nRet != 0 )
    {
        fprintf( stderr, "fail to make PKIReq : %d\n", nRet );
        manApplet->warningBox( "fail to make PKIReq", this );
        goto end;
    }

    strURL = QString( "%1?operation=PKIOperation").arg( strSCEPURL );

    nRet = JS_HTTP_requestPostBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                "application/x-pki-message",
                &binReq,               
                &nStatus,
                &binRsp );

    if( nRet != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        fprintf( stderr, "fail to request Post [%d:%d]\n", nRet, nStatus );
        manApplet->warningBox( "fail to request Post", this );
        goto end;
    }

    nRet = JS_SCEP_parseCertRsp(
                &binRsp,
                &binCACert,
                &binPri,
                &binSenderNonce,
                pTransID,
                &binSignedData );

    if( nRet != 0 )
    {
        fprintf( stderr, "fail to parse CertRsp : %d\n", nRet );
        manApplet->warningBox( "fail to parse CertRsp", this );
        goto end;
    }

//    JS_BIN_fileWrite( &binSignedData, "D:/jsca/res_signeddata.ber" );

    nRet = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNewCert );
    if( nRet != 0 )
    {
        fprintf( stderr, "fail to get sign certificate in reply: %d\n", nRet );
        manApplet->warningBox( "fail to get sign certificate in reply", this );
        goto end;
    }

    writeCertDB( db_mgr_, &binNewCert );

    manApplet->mainWindow()->createRightCertList(-2);

end :
    JS_BIN_reset( &binSSLPri );
    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binCACert );
    JS_BIN_reset( &binCSR );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binSenderNonce );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binSignedData );
    JS_BIN_reset( &binNewCert );

    if( pTransID ) JS_free( pTransID );
    if( pHex ) JS_free( pHex );
}

void MainWindow::renewSCEP()
{
    int ret = 0;
    int nKeyNum = -1;
    int nKeyType = -1;
    int nOption = -1;
    BIN binCert = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    BIN binNPub = {0,0};
    BIN binNPri = {0,0};
    BIN binCSR = {0,0};

    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};
    BIN binSenderNonce = {0,0};
    char *pTransID = NULL;
    int nStatus = 0;
    BIN binCACert = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binSignedData = {0,0};
    BIN binNCert = {0,0};

    JCertInfo   sCertInfo;

    const char *pChallengePass = "1111";

    SettingsMgr *smgr = manApplet->settingsMgr();

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    if( smgr->SCEPURI() == false ) return;

    QString strSCEPURL = smgr->SCEPURI();
    QString strURL;

    CertRec certRec;
    KeyPairRec keyPair;

    db_mgr_->getCertRec( num, certRec );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( certRec.getKeyNum() < 0 )
    {
        manApplet->warningBox( tr( "The certificate has not keypair in this tool"), this );
        goto end;
    }

    db_mgr_->getKeyPairRec( certRec.getKeyNum(), keyPair );
    JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
    if( ret !=  0)
    {
        manApplet->warningBox( tr("fail to decode certificate"), this );
        goto end;
    }

    JS_PKI_getPubKeyFromCert( &binCert, &binPub );
    JS_PKI_getPubKeyInfo( &binPub, &nKeyType, &nOption );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        ret = JS_PKI_RSAGenKeyPair( nOption, 63357, &binNPub, &binNPri );
    else if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        ret = JS_PKI_ECCGenKeyPair( nOption, &binNPub, &binNPri );

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to generate keypair"), this );
        goto end;
    }

    nKeyNum = writeKeyPairDB( db_mgr_, sCertInfo.pSubjectName, &binNPub, &binNPri );

    ret = JS_PKI_makeCSR( nKeyType, "SHA256", sCertInfo.pSubjectName, pChallengePass, &binNPri, NULL, &binCSR );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to make csr"), this );
        goto end;
    }

    writeCSRDB( db_mgr_, nKeyNum, "SCEP Update", sCertInfo.pSubjectName, "SHA256", &binCSR );

    if( smgr->SCEPMutualAuth() )
    {
        QString strCertPath = smgr->SCEPCertPath();
        QString strPriPath = smgr->SCEPPriKeyPath();

        JS_BIN_fileRead( strCertPath.toLocal8Bit().toStdString().c_str(), &binSSLCert );
        JS_BIN_fileRead( strPriPath.toLocal8Bit().toStdString().c_str(), &binSSLPri );
    }

    JS_PKI_genRandom( 16, &binSenderNonce );
    JS_SCEP_makeTransID( &binCSR, &pTransID );

    strURL = QString( "%1?operation=GetCACert" ).arg( strSCEPURL );

    ret = JS_HTTP_requestGetBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                &nStatus,
                &binCACert );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        fprintf( stderr, "fail to request Get [%d:%d]\n", ret, nStatus );
        manApplet->warningBox( "fail to request Get", this );
        goto end;
    }


    ret = JS_SCEP_makePKIReq(
                &binCSR,
                &binPri,
                &binCert,
                &binCACert,
                &binSenderNonce,
                pTransID,
                &binReq );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to make PKIReq : %d\n", ret );
        manApplet->warningBox( "fail to make PKIReq", this );
        goto end;
    }

    strURL = QString( "%1?operation=PKIOperation").arg( strSCEPURL );

    ret = JS_HTTP_requestPostBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                "application/x-pki-message",
                &binReq,
                &nStatus,
                &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        fprintf( stderr, "fail to request Post [%d:%d]\n", ret, nStatus );
        manApplet->warningBox( "fail to request Post", this );
        goto end;
    }

    ret = JS_SCEP_parseCertRsp(
                &binRsp,
                &binCACert,
                &binPri,
                &binSenderNonce,
                pTransID,
                &binSignedData );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to parse CertRsp : %d\n", ret );
        manApplet->warningBox( "fail to parse CertRsp", this );
        goto end;
    }

    ret = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNCert );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to get sign certificate in reply: %d\n", ret );
        manApplet->warningBox( "fail to get sign certificate in reply", this );
        goto end;
    }

    writeCertDB( db_mgr_, &binNCert );

    manApplet->mainWindow()->createRightCertList(-2);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binNPri );
    JS_BIN_reset( &binNPub );
    JS_BIN_reset( &binCSR );
    JS_PKI_resetCertInfo( &sCertInfo );

    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );
    JS_BIN_reset( &binSenderNonce );
    JS_BIN_reset( &binCACert );
    if( pTransID ) JS_free( pTransID );
    JS_BIN_reset( &binSignedData );
    JS_BIN_reset( &binNCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void MainWindow::getCRLSCEP()
{
    int ret = 0;
    int nKeyNum = -1;
    int nKeyType = -1;
    int nOption = -1;
    BIN binCert = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};
    BIN binSenderNonce = {0,0};

    int nStatus = 0;
    BIN binCACert = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binSignedData = {0,0};
    BIN binCRL = {0,0};


    const char *pTransID = "1111";

    SettingsMgr *smgr = manApplet->settingsMgr();

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    if( smgr->SCEPURI() == false ) return;

    QString strSCEPURL = smgr->SCEPURI();
    QString strURL;

    CertRec certRec;
    KeyPairRec keyPair;

    db_mgr_->getCertRec( num, certRec );

    if( certRec.getKeyNum() < 0 )
    {
        manApplet->warningBox( tr( "The certificate has not keypair in this tool"), this );
        goto end;
    }

    db_mgr_->getKeyPairRec( certRec.getKeyNum(), keyPair );
    JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );

    if( smgr->SCEPMutualAuth() )
    {
        QString strCertPath = smgr->SCEPCertPath();
        QString strPriPath = smgr->SCEPPriKeyPath();

        JS_BIN_fileRead( strCertPath.toLocal8Bit().toStdString().c_str(), &binSSLCert );
        JS_BIN_fileRead( strPriPath.toLocal8Bit().toStdString().c_str(), &binSSLPri );
    }

    JS_PKI_genRandom( 16, &binSenderNonce );


    strURL = QString( "%1?operation=GetCACert" ).arg( strSCEPURL );

    ret = JS_HTTP_requestGetBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                &nStatus,
                &binCACert );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        fprintf( stderr, "fail to request Get [%d:%d]\n", ret, nStatus );
        manApplet->warningBox( "fail to request Get", this );
        goto end;
    }

    ret = JS_SCEP_makeGetCRL( &binCert, &binPri, &binCert, &binCACert, &binSenderNonce, pTransID, &binReq );


    if( ret != 0 )
    {
        fprintf( stderr, "fail to make getCRL : %d\n", ret );
        manApplet->warningBox( "fail to make PKIReq", this );
        goto end;
    }

    strURL = QString( "%1?operation=PKIOperation").arg( strSCEPURL );

    ret = JS_HTTP_requestPostBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                "application/x-pki-message",
                &binReq,
                &nStatus,
                &binRsp );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        fprintf( stderr, "fail to request Post [%d:%d]\n", ret, nStatus );
        manApplet->warningBox( "fail to request Post", this );
        goto end;
    }

    ret = JS_SCEP_parseCertRsp(
                &binRsp,
                &binCACert,
                &binPri,
                &binSenderNonce,
                pTransID,
                &binSignedData );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to parse CertRsp : %d\n", ret );
        manApplet->warningBox( "fail to parse CertRsp", this );
        goto end;
    }

    ret = JS_SCEP_getCRL( &binSignedData, &binCRL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to get crl in reply: %d\n", ret );
        manApplet->warningBox( "fail to get crl in reply", this );
        goto end;
    }

    writeCRLDB( db_mgr_, &binCRL );

    manApplet->mainWindow()->createRightCRLList(-2);

end :
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binPri );


    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );
    JS_BIN_reset( &binSenderNonce );
    JS_BIN_reset( &binCACert );
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binSignedData );

    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
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

void MainWindow::checkOCSP()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    bool bVal = manApplet->settingsMgr()->OCSPUse();
    if( bVal == false )
    {
        manApplet->warningBox( tr( "OCSP settinsg is not set" ), this );
        return;
    }

    int nStatus = 0;

    BIN binCA = {0,0};
    BIN binCert = {0,0};
    BIN binSignCert = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};


    CertRec caRec;
    CertRec certRec;

    JCertIDInfo sIDInfo;
    JCertStatusInfo sStatusInfo;

    QString strURL;
    QString strOCSPSrvCert;
    QString strStatus;

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));

    db_mgr_->getCertRec( num, certRec );
    db_mgr_->getCertRec( certRec.getIssuerNum(), caRec );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    JS_BIN_decodeHex( caRec.getCert().toStdString().c_str(), &binCA );

    ret = JS_OCSP_encodeRequest( &binCert, &binCA, "SHA1", NULL, NULL, &binReq );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to encode request" ), this );
        goto end;
    }

    strURL = manApplet->settingsMgr()->OCSPURI();
    strURL += "/OCSP";
    strOCSPSrvCert = manApplet->settingsMgr()->OCSPSrvCertPath();

    JS_BIN_fileRead( strOCSPSrvCert.toLocal8Bit().toStdString().c_str(), &binSignCert );

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/ocsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to request"), this );
        goto end;
    }


    ret = JS_OCSP_decodeResponse( &binRsp, &binSignCert, &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to decode respose" ), this );
        goto end;
    }

    if( sStatusInfo.nStatus == JS_OCSP_STATUS_GOOD )
        strStatus = "GOOD";
    else if( sStatusInfo.nStatus == JS_OCSP_STATUS_UNKNOWN )
        strStatus = "UNKNOWN";
    else if( sStatusInfo.nStatus == JS_OCSP_STATUS_REVOKED )
        strStatus = QString( "Revoked[ Reason : %1, RevokedTime : %2]" ).arg( sStatusInfo.nReason ).arg( sStatusInfo.nRevokedTime );

    manApplet->messageBox( strStatus, this );

 end :

    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
}

void MainWindow::tsp()
{
    TSPDlg tspDlg;
    tspDlg.exec();
}

void MainWindow::statusByReg()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    JRegCertStatusReq sStatusReq;
    JRegCertStatusRsp sStatusRsp;

    char *pReq = NULL;
    char *pRsp = NULL;
    int nStatus = -1;

    memset( &sStatusReq, 0x00, sizeof(sStatusReq));
    memset( &sStatusRsp, 0x00, sizeof(sStatusRsp));

    CertRec cert;
    db_mgr_->getCertRec( num, cert );

    JS_JSON_setRegCertStatusReq( &sStatusReq, "name", cert.getSubjectDN().toStdString().c_str() );

    SettingsMgr *mgr = manApplet->settingsMgr();
    QString strURL;

    if( mgr->REGUse() == false )
    {
        manApplet->warningBox( tr( "REGServer is not set" ), this );
        return;
    }

    strURL = mgr->REGURI();
    strURL += "/certstatus";

    JS_JSON_encodeRegCertStatusReq( &sStatusReq, &pReq );

    JS_HTTP_requestPost( strURL.toStdString().c_str(), pReq, "application/json", &nStatus, &pRsp );

    JS_JSON_decodeRegCertStatusRsp( pRsp, &sStatusRsp );

    if( strcasecmp( sStatusRsp.pResCode, "0000" ) == 0 )
    {
        QString strStatus = sStatusRsp.pStatus;
        manApplet->messageBox( strStatus, this );
        ret = 0;
    }
    else
    {
        manApplet->warningBox( "fail to get certificate status by REGServer" );
        ret = -1;
    }

    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );
    JS_JSON_resetRegCertStatusReq( &sStatusReq );
    JS_JSON_resetRegCertStatusRsp( &sStatusRsp );
}

void MainWindow::revokeByReg()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    JRegCertRevokeReq     sRevokeReq;
    JRegCertRevokeRsp     sRevokeRsp;

    char *pReq = NULL;
    char *pRsp = NULL;
    int nStatus = -1;

    memset( &sRevokeReq, 0x00, sizeof(sRevokeReq));
    memset( &sRevokeRsp, 0x00, sizeof(sRevokeRsp));

    SettingsMgr *mgr = manApplet->settingsMgr();
    QString strURL;

    if( mgr->REGUse() == false )
    {
        manApplet->warningBox( tr( "REGServer is not set" ), this );
        return;
    }

    CertRec cert;
    db_mgr_->getCertRec( num, cert );

    strURL = mgr->REGURI();
    strURL += "/certrevoke";

    JS_JSON_setRegCertRevokeReq( &sRevokeReq, "name", cert.getSubjectDN().toStdString().c_str(), "1" );

    JS_JSON_encodeRegCertRevokeReq( &sRevokeReq, &pReq );

    JS_HTTP_requestPost( strURL.toStdString().c_str(), pReq, "application/json", &nStatus, &pRsp );

    JS_JSON_decodeRegRsp( pRsp, &sRevokeRsp );

    if( strcasecmp( sRevokeRsp.pResCode, "0000" ) == 0 )
    {
        manApplet->messageBox( tr("Revoke is success"), this );
        ret = 0;
    }
    else
    {
        manApplet->warningBox( "fail to revoke certificate by REGServer" );
        ret = -1;
    }

    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    JS_JSON_resetRegCertRevokeReq( &sRevokeReq );
    JS_JSON_resetRegRsp( &sRevokeRsp );
}

void MainWindow::createRightList( int nType, int nNum )
{
    stack_->setCurrentIndex(0);

    if( nType == CM_ITEM_TYPE_KEYPAIR )
        createRightKeyPairList();
    else if( nType == CM_ITEM_TYPE_REQUEST )
        createRightRequestList();
    else if( nType == CM_ITEM_TYPE_CERT_PROFILE )
        createRightCertProfileList();
    else if( nType == CM_ITEM_TYPE_CRL_PROFILE )
        createRightCRLProfileList();
    else if( nType == CM_ITEM_TYPE_ROOTCA )
        createRightCertList( -1 );
    else if( nType == CM_ITEM_TYPE_IMPORT_CERT )
        createRightCertList( -2 );
    else if( nType == CM_ITEM_TYPE_IMPORT_CRL )
        createRightCRLList( -2 );
    else if( nType == CM_ITEM_TYPE_CA )
        createRightCertList( nNum );
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
    else if( nType == CM_ITEM_TYPE_ADMIN )
        createRightAdminList();
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
    else if( nType == CM_ITEM_TYPE_TSP )
        createRightTSPList();
}

void MainWindow::createRightKeyPairList()
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_KEYPAIR;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Algorithm"), tr("Name"), tr("Param"), tr("Status") };

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

    right_table_->setColumnWidth( 0, 40 ); // Number
    right_table_->setColumnWidth( 1, 140 ); // RegTime
    right_table_->setColumnWidth( 2, 80 );
    right_table_->setColumnWidth( 3, 300 );
    right_table_->setColumnWidth( 4, 60 );
    right_table_->setColumnWidth( 5, 60 );

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        char sRegTime[64];
        KeyPairRec keyPairRec = keyPairList.at(i);

        JS_UTIL_getDateTime( keyPairRec.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(keyPairRec.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg(sRegTime)));
        right_table_->setItem( i, 2, new QTableWidgetItem( keyPairRec.getAlg()));
        right_table_->setItem( i, 3, new QTableWidgetItem( keyPairRec.getName()));
        right_table_->setItem(i, 4, new QTableWidgetItem( keyPairRec.getParam()));
        right_table_->setItem(i, 5, new QTableWidgetItem( QString("%1").arg(getRecStatusName(keyPairRec.getStatus()))));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}


void MainWindow::createRightRequestList()
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_REQUEST;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Key"), tr("Name"), tr("Hash"), tr("Status"), tr("DN") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
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

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 140 );
    right_table_->setColumnWidth( 3, 140 );
    right_table_->setColumnWidth( 4, 60 );
    right_table_->setColumnWidth( 5, 60 );

    for( int i=0; i < reqList.size(); i++ )
    {
        char sRegTime[64];
        ReqRec reqRec = reqList.at(i);
        JS_UTIL_getDateTime( reqRec.getRegTime(), sRegTime );

        QString strKeyName = db_mgr_->getNumName( reqRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg( reqRec.getSeq() ) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sRegTime ) ));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strKeyName ) ));
        right_table_->setItem( i, 3, new QTableWidgetItem( reqRec.getName() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( reqRec.getHash() ));
        right_table_->setItem( i, 5, new QTableWidgetItem( QString("%1").arg( getRecStatusName(reqRec.getStatus()) )));
        right_table_->setItem( i, 6, new QTableWidgetItem( reqRec.getDN() ));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightCertProfileList()
{
    search_menu_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CERT_PROFILE;

    QStringList headerList = { tr("Num"), tr("Name"), tr("Version"), tr("NotBerfoer"), tr("NotAfter"), tr("Hash"), tr("DNTemplate") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CertProfileRec> certProfileList;
    db_mgr_->getCertProfileList( certProfileList );

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 200 );
    right_table_->setColumnWidth( 2, 50 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 60 );

    for( int i=0; i < certProfileList.size(); i++ )
    {
        CertProfileRec certProfile = certProfileList.at(i);
        QString strVersion;
        QString strNotBefore;
        QString strNotAfter;
        QString strDNTemplate;

        strVersion = QString( "V%1" ).arg( certProfile.getVersion() + 1);

        if( certProfile.getNotBefore() == 0 )
        {
            strNotBefore = "GenTime";
            strNotAfter = QString( "%1 Days" ).arg( certProfile.getNotAfter() );
        }
        else
        {
            strNotBefore = getDateTime( certProfile.getNotBefore() );
            strNotAfter = getDateTime( certProfile.getNotAfter() );
        }

        if( certProfile.getDNTemplate() == "#CSR" )
            strDNTemplate = "Use CSR DN";
        else
            strDNTemplate = certProfile.getDNTemplate();

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(certProfile.getNum()) ));
        right_table_->setItem( i, 1, new QTableWidgetItem( certProfile.getName() ));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strVersion )));
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg( strNotBefore )));
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg( strNotAfter )));
        right_table_->setItem( i, 5, new QTableWidgetItem( certProfile.getHash() ));
        right_table_->setItem( i, 6, new QTableWidgetItem( strDNTemplate ));
    }
}

void MainWindow::createRightCRLProfileList()
{
    search_menu_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CRL_PROFILE;

    QStringList headerList = { tr("Num"), tr("Name"), tr("Version"), tr("LastUpdate"), tr("NextUpdate"), tr("Hash") };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(6);
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);


    QList<CRLProfileRec> crlProfileList;
    db_mgr_->getCRLProfileList( crlProfileList );

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 300 );
    right_table_->setColumnWidth( 2, 50 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 60 );

    for( int i=0; i < crlProfileList.size(); i++ )
    {
        CRLProfileRec crlProfile = crlProfileList.at(i);

        QString strVersion;
        QString strLastUpdate;
        QString strNextUpdate;

        strVersion = QString( "V%1" ).arg( crlProfile.getVersion() + 1);

        if( crlProfile.getLastUpdate() == 0 )
        {
            strLastUpdate = "GenTime";
            strNextUpdate = QString( "%1 Days" ).arg( crlProfile.getNextUpdate() );
        }
        else
        {
            strLastUpdate = getDateTime( crlProfile.getLastUpdate() );
            strNextUpdate = getDateTime( crlProfile.getNextUpdate() );
        }

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crlProfile.getNum() )) );
        right_table_->setItem( i, 1, new QTableWidgetItem( crlProfile.getName()) );
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strVersion )) );
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg( strLastUpdate )) );
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg( strNextUpdate )) );
        right_table_->setItem( i, 5, new QTableWidgetItem( crlProfile.getHash()) );
    }
}

void MainWindow::createRightCertList( int nIssuerNum, bool bIsCA )
{
    search_menu_->show();
    removeAllRight();
    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    right_type_ = RightType::TYPE_CERTIFICATE;

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Key"), tr("User"), tr("SignAlg"), tr("Issuer"), tr("SubjectDN") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QList<CertRec> certList;

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 100 );

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

        QString strKeyName = db_mgr_->getNumName( cert.getKeyNum(), "TB_KEY_PAIR", "NAME" );
        QString strUserName = db_mgr_->getNumName( cert.getUserNum(), "TB_USER", "NAME" );
        QString strIsserName = db_mgr_->getNumName( cert.getIssuerNum(), "TB_CERT", "SUBJECTDN" );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( cert.getNum()) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( sRegTime ) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( strKeyName )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( strUserName )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( cert.getSignAlg() ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( strIsserName )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( strDNInfo ));
//        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg(cert.getCRLDP() )));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightCRLList( int nIssuerNum )
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_CRL;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;
    char sRegTime[64];

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Issuer"), tr("SignAlg"), tr("CRLDP") };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CRLRec> crlList;

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 200 );
    right_table_->setColumnWidth( 3, 200 );


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
        QString strIssuerName = db_mgr_->getNumName( crl.getIssuerNum(), "TB_CERT", "SUBJECTDN" );

        JS_UTIL_getDateTime( crl.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crl.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sRegTime )));
        right_table_->setItem( i, 2, new QTableWidgetItem(QString("%1").arg( strIssuerName )));
        right_table_->setItem( i, 3, new QTableWidgetItem( crl.getSignAlg() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( crl.getCRLDP() ));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightRevokeList(int nIssuerNum)
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_REVOKE;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Num"), tr("Cert"), tr("Issuer"), tr("Serial"), tr("RevokeDate"), tr("Reason"), tr("CRLDP") };

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

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 120 );
    right_table_->setColumnWidth( 2, 120 );
    right_table_->setColumnWidth( 3, 60 );
    right_table_->setColumnWidth( 4, 140 );
    right_table_->setColumnWidth( 5, 120 );

    for( int i=0; i < revokeList.size(); i++ )
    {
        RevokeRec revoke = revokeList.at(i);

        QString strCertName = db_mgr_->getNumName( revoke.getCertNum(), "TB_CERT", "SUBJECTDN" );
        QString strIsserName = db_mgr_->getNumName( revoke.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
        QString strReason = JS_PKI_getRevokeReasonName( revoke.getReason() );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg(revoke.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( strCertName )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( strIsserName )));
        right_table_->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(revoke.getSerial())));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg(getDateTime( revoke.getRevokeDate() ))));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( strReason )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg(revoke.getCRLDP())));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightUserList()
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_USER;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Name"), tr("SSN"), tr("Email"), tr("Status") };

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

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 180 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 180 );
    right_table_->setColumnWidth( 5, 60 );


    for( int i = 0; i < userList.size(); i++ )
    {
        char sRegTime[64];
        UserRec user = userList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        JS_UTIL_getDateTime( user.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( user.getNum() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( user.getName())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( user.getSSN() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( user.getEmail() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( getUserStatusName( user.getStatus() ) )));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightKMSList()
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_KMS;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Status"), tr("Type"), tr("Algorithm"), tr("ID"), tr("Info") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<KMSRec> kmsList;

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 100 );

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
        right_table_->setRowHeight(i, 10 );

        QString strType = JS_KMS_getObjectTypeName( kms.getType() );
        QString strAlgorithm = JS_PKI_getKeyTypeName( kms.getAlgorithm() );

        JS_UTIL_getDateTime( kms.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( kms.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getStatusName( kms.getState() ))));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( strType )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( strAlgorithm )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( kms.getID() )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg( kms.getInfo() )));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightSignerList(int nType)
{
    search_menu_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_SIGNER;

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Type"), tr("DN"), tr("Status"), tr("DNHash") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<SignerRec> signerList;
    db_mgr_->getSignerList( nType, signerList );


    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 80 );
    right_table_->setColumnWidth( 3, 200 );
    right_table_->setColumnWidth( 4, 60 );

    for( int i = 0; i < signerList.size(); i++ )
    {
        char sRegTime[64];
        SignerRec signer = signerList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );

        JS_UTIL_getDateTime( signer.getRegTime(), sRegTime );
        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( signer.getNum() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getSignerTypeName( signer.getType() ))));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( signer.getDN() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( getStatusName( signer.getStatus() ))));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( signer.getDNHash() )));
    }
}

void MainWindow::createRightAdminList()
{
    search_menu_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_ADMIN;

    QStringList headerList = { tr("Seq"), tr("Status"), tr("Type"), tr("Name"), tr("Password"), tr("Email") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<AdminRec> adminList;
    db_mgr_->getAdminList( adminList );

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 60 );
    right_table_->setColumnWidth( 3, 160 );
    right_table_->setColumnWidth( 4, 160 );


    for( int i = 0; i < adminList.size(); i++ )
    {
        AdminRec admin = adminList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( admin.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( getStatusName( admin.getStatus() ) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getAdminTypeName( admin.getType() ) )));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( admin.getName() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( admin.getPassword() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( admin.getEmail() )));
    }
}


void MainWindow::createRightAuditList()
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_AUDIT;

    int nTotalCount = 0;
//    int nLimit = kListCount;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Kind"), tr("Operation"), tr("UserName"), tr("Info"), tr("MAC") };

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

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 100 );

    for( int i = 0; i < auditList.size(); i++ )
    {
        char sRegTime[64];
        AuditRec audit = auditList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        QString strKind = JS_GEN_getKindName( audit.getKind() );
        QString strOperation = JS_GEN_getOperationName( audit.getOperation() );

        JS_UTIL_getDateTime( audit.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( audit.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( strKind )));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( strOperation )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( audit.getUserName() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( audit.getInfo() )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg( audit.getMAC() )));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightTSPList()
{
    search_menu_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_TSP;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_menu_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_menu_->getCondName();
    QString strWord = search_menu_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Serial"), tr("SrcHash"), tr("Policy") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<TSPRec> tspList;

    if( strWord.length() > 0 )
    {
        nTotalCount = db_mgr_->getTSPSearchCount( strTarget, strWord );
        db_mgr_->getTSPList( strTarget, strWord, nOffset, nLimit, tspList );
    }
    else
    {
        nTotalCount = db_mgr_->getAuditCount();
        db_mgr_->getTSPList( nOffset, nLimit, tspList );
    }

    right_table_->setColumnWidth( 0, 40 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 200 );

    for( int i = 0; i < tspList.size(); i++ )
    {
        char sRegTime[64];
        TSPRec tsp = tspList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        JS_UTIL_getDateTime( tsp.getRegTime(), sRegTime );

        right_table_->setItem(i,0, new QTableWidgetItem(QString("%1").arg( tsp.getSeq() )));
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( tsp.getSerial())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( tsp.getSrcHash() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( tsp.getPolicy() )));
    }

    search_menu_->setTotalCount( nTotalCount );
    search_menu_->updatePageLabel();
}

void MainWindow::createRightStatistics()
{
    printf( "Set Statistics\n" );
    //stack_->addWidget( statistics_ );
    stack_->setCurrentIndex(1);
}

void MainWindow::logKeyPair(int seq)
{
    if( db_mgr_ == NULL ) return;
    KeyPairRec keyPair;

    db_mgr_->getKeyPairRec( seq, keyPair );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== KeyPair Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num        : %1\n").arg( keyPair.getNum() ));
    manApplet->log( QString("Algorithm  : %1\n").arg(keyPair.getAlg()));
    manApplet->log( QString("Name       : %1\n").arg(keyPair.getName()));
    manApplet->log( QString("PublicKey  : %1\n").arg(keyPair.getPublicKey()));
    manApplet->log( QString("PrivateKey : %1\n").arg(keyPair.getPrivateKey()));
    manApplet->log( QString("Param      : %1\n").arg(keyPair.getParam()));
    manApplet->log( QString("Status     : %1 - %2\n").arg(keyPair.getStatus()).arg(getRecStatusName(keyPair.getStatus())));

    logCurorTop();
}

void MainWindow::logRequest( int seq )
{
    if( db_mgr_ == NULL ) return;

    ReqRec reqRec;
    db_mgr_->getReqRec( seq, reqRec );

    QString strKeyName = db_mgr_->getNumName( reqRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Request Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("SEQ      : %1\n").arg(reqRec.getSeq()));
    manApplet->log( QString("KeyNum   : %1 - %2\n").arg(reqRec.getKeyNum()).arg( strKeyName ));
    manApplet->log( QString("Name     : %1\n").arg(reqRec.getName()));
    manApplet->log( QString("DN       : %1\n").arg(reqRec.getDN()));
    manApplet->log( QString("Request  : %1\n").arg(reqRec.getCSR()));
    manApplet->log( QString("Hash     : %1\n").arg(reqRec.getHash()));
    manApplet->log( QString("Status   : %1 - %2\n").arg(reqRec.getStatus()).arg( getRecStatusName(reqRec.getStatus())));

    logCurorTop();
}

void MainWindow::logCertificate( int seq )
{
    if( db_mgr_ == NULL ) return;

    char    sRegDate[64];

    CertRec certRec;
    db_mgr_->getCertRec( seq, certRec );

    QString strKeyName = db_mgr_->getNumName( certRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );
    QString strUserName = db_mgr_->getNumName( certRec.getUserNum(), "TB_USER", "NAME" );
    QString strIsserName = db_mgr_->getNumName( certRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Certificate Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num           : %1\n").arg(certRec.getNum()));
    JS_UTIL_getDateTime( certRec.getRegTime(), sRegDate );
    manApplet->log( QString("RegDate       : %1\n").arg(sRegDate));
    manApplet->log( QString("KeyNum        : %1 - %2\n").arg(certRec.getKeyNum()).arg( strKeyName ));
    manApplet->log( QString("UserNum       : %1 - %2\n").arg(certRec.getUserNum()).arg( strUserName ));
    manApplet->log( QString("SignAlgorithm : %1\n").arg(certRec.getSignAlg()));
    manApplet->log( QString("Certificate   : %1\n").arg(certRec.getCert()));
    manApplet->log( QString("IsCA          : %1\n").arg(certRec.isCA()));
    manApplet->log( QString("IsSelf        : %1\n").arg(certRec.isSelf()));
    manApplet->log( QString("SubjectDN     : %1\n").arg(certRec.getSubjectDN()));
    manApplet->log( QString("IssuerNum     : %1 - %2\n").arg(certRec.getIssuerNum()).arg( strIsserName ));
    manApplet->log( QString("Status        : %1 - %2\n").arg(certRec.getStatus()).arg( getCertStatusName( certRec.getStatus() )));
    manApplet->log( QString("Serial        : %1\n").arg(certRec.getSerial()));
    manApplet->log( QString("DNHash        : %1\n").arg(certRec.getDNHash()));
    manApplet->log( QString("KeyHash       : %1\n").arg(certRec.getKeyHash()));
    manApplet->log( QString("CRLDP         : %1\n").arg(certRec.getCRLDP()));

    logCurorTop();
}

void MainWindow::logCertProfile( int seq )
{
    if( db_mgr_ == NULL ) return;

    CertProfileRec certProfile;

    db_mgr_->getCertProfileRec( seq, certProfile );

    QString strVersion;
    QString strNotBefore;
    QString strNotAfter;
    QString strDNTemplate;

    strVersion = QString( "V%1" ).arg( certProfile.getVersion() + 1);

    if( certProfile.getNotBefore() == 0 )
    {
        strNotBefore = "GenTime";
        strNotAfter = QString( "%1 Days" ).arg( certProfile.getNotAfter() );
    }
    else
    {
        strNotBefore = getDateTime( certProfile.getNotBefore() );
        strNotAfter = getDateTime( certProfile.getNotAfter() );
    }

    if( certProfile.getDNTemplate() == "#CSR" )
        strDNTemplate = "Use CSR DN";
    else
        strDNTemplate = certProfile.getDNTemplate();

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Certificate Profile Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num         : %1\n").arg(certProfile.getNum()));
    manApplet->log( QString("Name        : %1\n").arg(certProfile.getName()));
    manApplet->log( QString("Version     : %1 - %2\n").arg(certProfile.getVersion()).arg( strVersion ));
    manApplet->log( QString("NotBefore   : %1 - %2\n").arg(certProfile.getNotBefore()).arg(strNotBefore));
    manApplet->log( QString("NotAfter    : %1 - %2\n").arg(certProfile.getNotAfter()).arg(strNotAfter));
    manApplet->log( QString("Hash        : %1\n").arg(certProfile.getHash()));
    manApplet->log( QString("DNTemplate  : %1 - %2\n").arg(certProfile.getDNTemplate()).arg(strDNTemplate));
    manApplet->log( "======================= Extension Information ==========================\n" );
    QList<ProfileExtRec> extList;
    db_mgr_->getCertProfileExtensionList( seq, extList );

    for( int i = 0; i < extList.size(); i++ )
    {
        ProfileExtRec extRec = extList.at(i);

        manApplet->log( QString( "%1 || %2 || %3 || %4\n")
                .arg(extRec.getSeq())
                .arg(extRec.isCritical())
                .arg(extRec.getSN())
                .arg(extRec.getValue()) );
    }

    logCurorTop();
}

void MainWindow::logCRL( int seq )
{
    if( db_mgr_ == NULL ) return;

    CRLRec crlRec;
    char    sRegTime[64];

    db_mgr_->getCRLRec( seq, crlRec );
    QString strIssuerName = db_mgr_->getNumName( crlRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== CRL Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num           : %1\n").arg(crlRec.getNum()));
    JS_UTIL_getDateTime( crlRec.getRegTime(), sRegTime );
    manApplet->log( QString("RegTime       : %1\n").arg(sRegTime));
    manApplet->log( QString("IssuerNum     : %1 - %2\n").arg(crlRec.getIssuerNum()).arg( strIssuerName ));
    manApplet->log( QString("SignAlgorithm : %1\n").arg(crlRec.getSignAlg()));
    manApplet->log( QString("CRLDP         : %1\n").arg(crlRec.getCRLDP()));
    manApplet->log( QString("CRL           : %1\n").arg(crlRec.getCRL()));

    logCurorTop();
}

void MainWindow::logCRLProfile( int seq )
{
    if( db_mgr_ == NULL ) return;

    CRLProfileRec crlProfile;

    db_mgr_->getCRLProfileRec( seq, crlProfile );

    QString strVersion;
    QString strLastUpdate;
    QString strNextUpdate;

    strVersion = QString( "V%1" ).arg( crlProfile.getVersion() + 1);

    if( crlProfile.getLastUpdate() == 0 )
    {
        strLastUpdate = "GenTime";
        strNextUpdate = QString( "%1 Days" ).arg( crlProfile.getNextUpdate() );
    }
    else
    {
        strLastUpdate = getDateTime( crlProfile.getLastUpdate() );
        strNextUpdate = getDateTime( crlProfile.getNextUpdate() );
    }

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== CRL Profile Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num          : %1\n").arg(crlProfile.getNum()));
    manApplet->log( QString("Name         : %1\n").arg(crlProfile.getName()));
    manApplet->log( QString("Version      : %1 - %2\n").arg(crlProfile.getVersion()).arg(strVersion));
    manApplet->log( QString("LastUpdate   : %1 - %2\n").arg(crlProfile.getLastUpdate()).arg(strLastUpdate));
    manApplet->log( QString("NextUpdate   : %1 - %2\n").arg(crlProfile.getNextUpdate()).arg(strNextUpdate));
    manApplet->log( QString("Hash         : %1\n").arg(crlProfile.getHash()));
    manApplet->log( "======================= Extension Information ==========================\n" );

    QList<ProfileExtRec> extList;
    db_mgr_->getCRLProfileExtensionList( seq, extList );

    for( int i = 0; i < extList.size(); i++ )
    {
        ProfileExtRec extRec = extList.at(i);

        manApplet->log( QString( "%1 || %2 || %3 || %4\n")
                .arg(extRec.getSeq())
                .arg(extRec.isCritical())
                .arg(extRec.getSN())
                .arg(extRec.getValue()));
    }

    logCurorTop();
}

void MainWindow::logRevoke( int seq )
{
    if( db_mgr_ == NULL ) return;

    RevokeRec revokeRec;
    db_mgr_->getRevokeRec( seq, revokeRec );

    QString strCertName = db_mgr_->getNumName( revokeRec.getCertNum(), "TB_CERT", "SUBJECTDN" );
    QString strIsserName = db_mgr_->getNumName( revokeRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
    QString strReason = JS_PKI_getRevokeReasonName( revokeRec.getReason() );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Revoke Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Seq          : %1\n").arg( revokeRec.getSeq()));
    manApplet->log( QString("CertNum      : %1 - %2\n").arg( revokeRec.getCertNum()).arg(strCertName));
    manApplet->log( QString("IssuerNum    : %1 - %2\n").arg( revokeRec.getIssuerNum()).arg(strIsserName));
    manApplet->log( QString("Serial       : %1\n").arg( revokeRec.getSerial()));
    manApplet->log( QString("RevokeDate   : %1\n").arg( getDateTime( revokeRec.getRevokeDate() )));
    manApplet->log( QString("Reason       : %1 - %2\n").arg( revokeRec.getReason()).arg(strReason));
    manApplet->log( QString("CRLDP        : %1\n").arg( revokeRec.getCRLDP()));

    logCurorTop();
}

void MainWindow::logUser( int seq )
{
    if( db_mgr_ == NULL ) return;

    UserRec userRec;
    db_mgr_->getUserRec( seq, userRec );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== User Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num           : %1\n").arg(userRec.getNum()));
    manApplet->log( QString("RegTime       : %1\n").arg(getDateTime(userRec.getRegTime())));
    manApplet->log( QString("Name          : %1\n").arg(userRec.getName()));
    manApplet->log( QString("SSN           : %1\n").arg(userRec.getSSN()));
    manApplet->log( QString("Email         : %1\n").arg(userRec.getEmail()));
    manApplet->log( QString("Status        : %1 - %2\n").arg(userRec.getStatus()).arg(getUserStatusName(userRec.getStatus())));
    manApplet->log( QString("RefNum        : %1\n").arg(userRec.getRefNum()));
    manApplet->log( QString("AuthCode      : %1\n").arg(userRec.getAuthCode()));

    logCurorTop();
}

void MainWindow::logAdmin( int seq )
{
    if( db_mgr_ == NULL ) return;

    AdminRec adminRec;
    db_mgr_->getAdminRec( seq, adminRec );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Admin Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Seq          : %1\n").arg(adminRec.getSeq()));
    manApplet->log( QString("Status       : %1 - %2\n").arg(adminRec.getStatus()).arg(getStatusName(adminRec.getStatus())));
    manApplet->log( QString("Type         : %1 - %2\n").arg(adminRec.getType()).arg(getAdminTypeName(adminRec.getType())));
    manApplet->log( QString("Password     : %1\n").arg(adminRec.getPassword()));
    manApplet->log( QString("Email        : %1\n").arg(adminRec.getEmail()));

    logCurorTop();
}

void MainWindow::logKMS( int seq )
{
    if( db_mgr_ == NULL ) return;

    KMSRec kmsRec;
    db_mgr_->getKMSRec( seq, kmsRec );

    QString strType = JS_KMS_getObjectTypeName( kmsRec.getType() );
    QString strAlgorithm = JS_PKI_getKeyTypeName( kmsRec.getAlgorithm() );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== KMS Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Seq         : %1\n").arg(kmsRec.getSeq()));
    manApplet->log( QString("RegTime     : %1\n").arg(getDateTime(kmsRec.getRegTime())));
    manApplet->log( QString("State       : %1 - %2\n").arg(kmsRec.getState()).arg( getStatusName(kmsRec.getState())));
    manApplet->log( QString("Type        : %1 - %2\n").arg(kmsRec.getType()).arg(strType));
    manApplet->log( QString("Algorithm   : %1 - %2\n").arg(kmsRec.getAlgorithm()).arg( strAlgorithm ));
    manApplet->log( QString("ID          : %1\n").arg(kmsRec.getID()));
    manApplet->log( QString("Info        : %1\n").arg(kmsRec.getInfo()));
    manApplet->log( "============================ Attribute =================================\n" );

    QList<KMSAttribRec> kmsAttribList;
    db_mgr_->getKMSAttribList( seq, kmsAttribList );

    for( int i = 0; i < kmsAttribList.size(); i++ )
    {
        KMSAttribRec attribRec = kmsAttribList.at(i);

        manApplet->log( QString( "%1 || %2 || %3\n")
                .arg(attribRec.getNum())
                .arg(JS_KMS_attributeName(attribRec.getType()))
                .arg(attribRec.getValue()));
    }

    logCurorTop();
}

void MainWindow::logAudit( int seq )
{
    if( db_mgr_ == NULL ) return;

    AuditRec auditRec;
    db_mgr_->getAuditRec( seq, auditRec );

    QString strKind = JS_GEN_getKindName( auditRec.getKind() );
    QString strOperation = JS_GEN_getOperationName( auditRec.getOperation() );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Audit Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Seq          : %1\n").arg(auditRec.getSeq()));
    manApplet->log( QString("Kind         : %1 - %2\n").arg(auditRec.getKind()).arg(strKind));
    manApplet->log( QString("Operation    : %1 - %2\n").arg(auditRec.getOperation()).arg(strOperation));
    manApplet->log( QString("UserName     : %1\n").arg(auditRec.getUserName()));
    manApplet->log( QString("Info         : %1\n").arg(auditRec.getInfo()));
    manApplet->log( QString("MAC          : %1\n").arg(auditRec.getMAC()));

    logCurorTop();
}

void MainWindow::logTSP( int seq )
{
    if( db_mgr_ == NULL ) return;

    TSPRec tspRec;
    db_mgr_->getTSPRec( seq, tspRec );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== TSP Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Seq          : %1\n").arg(tspRec.getSeq()));
    manApplet->log( QString("RegTime      : %1\n").arg(getDateTime(tspRec.getRegTime())));
    manApplet->log( QString("Serial       : %1\n").arg(tspRec.getSerial()));
    manApplet->log( QString("Policy       : %1\n").arg(tspRec.getPolicy()));
    manApplet->log( QString("TSTInfo      : %1\n").arg(tspRec.getTSTInfo()));
    manApplet->log( QString("Data         : %1\n").arg(tspRec.getData()));

    logCurorTop();
}

void MainWindow::logSigner(int seq)
{
    if( db_mgr_ == NULL ) return;

    SignerRec signerRec;
    db_mgr_->getSignerRec( seq, signerRec );

    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Signer Information\n" );
    manApplet->log( "========================================================================\n" );
    manApplet->log( QString("Num          : %1\n").arg( signerRec.getNum()));
    manApplet->log( QString("RegTime      : %1\n").arg(getDateTime(signerRec.getRegTime())));
    manApplet->log( QString("Type         : %1 - %2\n").arg(signerRec.getType()).arg(getSignerTypeName(signerRec.getType())));
    manApplet->log( QString("DN           : %1\n").arg(signerRec.getDN()));
    manApplet->log( QString("DNHash       : %1\n").arg(signerRec.getDNHash()));
    manApplet->log( QString("Cert         : %1\n").arg(signerRec.getCert()));
    manApplet->log( QString("Status       : %1 - %2\n").arg(signerRec.getStatus()).arg(getStatusName(signerRec.getType())));
    manApplet->log( QString("Desc         : %1\n").arg(signerRec.getDesc()));

    logCurorTop();
}

void MainWindow::logStatistics()
{
    manApplet->mainWindow()->logClear();
    manApplet->log( "========================================================================\n" );
    manApplet->log( "== Statistics Information\n" );
    manApplet->log( "========================================================================\n" );

    logCurorTop();
}

int MainWindow::rightCount()
{
    return right_table_->rowCount();
}
