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
#include "js_pki_ext.h"
#include "js_pki_tools.h"

#include "commons.h"
#include "mainwindow.h"
//#include "ui_mainwindow.h"

#include "man_tree_item.h"
#include "man_tree_model.h"
#include "man_tree_view.h"
// #include "search_menu.h"
#include "search_form.h"

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
#include "lcn_info_dlg.h"

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
#include "config_rec.h"
#include "config_dlg.h"
#include "set_pass_dlg.h"
#include "login_dlg.h"
#include "pri_key_info_dlg.h"
#include "renew_cert_dlg.h"
#include "csr_info_dlg.h"
#include "remote_db_dlg.h"

const int kMaxRecentFiles = 10;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
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
    recent_file_list_.clear();

    delete root_ca_;
    delete stat_;

    delete left_tree_;
    delete left_model_;

    delete log_text_;
    delete info_text_;

    delete search_form_;
    delete stack_;
    delete right_table_;
    delete text_tab_;
    delete vsplitter_;
    delete hsplitter_;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    if( manApplet->dbMgr()->isOpen() )
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

ManTreeItem* MainWindow::currentTreeItem()
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

    right_table_ = new QTableWidget;
    left_model_ = new ManTreeModel(this);
    search_form_ = new SearchForm;

#ifdef Q_OS_MAC
    search_form_->setMaximumHeight( 30 );
#else
    search_form_->setMaximumHeight( 23 );
#endif

    left_tree_->setModel(left_model_);

    log_text_ = new QTextEdit();
    log_text_->setReadOnly(true);

    info_text_ = new QTextEdit();
    info_text_->setReadOnly(true);

    right_table_->setSelectionBehavior(QAbstractItemView::SelectRows); // 한라인 전체 선택
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);  // Edit 불가
    right_table_->setSelectionMode(QAbstractItemView::SingleSelection); // 하나만 선택 가능
//    right_table_->setAlternatingRowColors(true);
//    right_table_->setAttribute(Qt::WA_MacShowFocusRect, 0);
//    right_table_->setSortingEnabled(false);

    QWidget *rightWidget = new QWidget;

    stack_ = new QStackedLayout();
    stat_ = new StatForm;

    stack_->addWidget( vsplitter_ );
    stack_->addWidget( stat_ );
    rightWidget->setLayout(stack_);

    hsplitter_->addWidget(left_tree_);
    hsplitter_->addWidget( rightWidget );

    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget( search_form_ );

    text_tab_ = new QTabWidget;
    vsplitter_->addWidget(text_tab_);
    text_tab_->setTabPosition( QTabWidget::South );
    text_tab_->addTab( info_text_, tr( "Information" ));

    QList <int> vsizes;
#ifdef Q_OS_MAC
    vsizes << 760 << 20 << 600;
#else
    vsizes << 760 << 10 << 600;
#endif

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

#ifdef Q_OS_MAC
    fileToolBar->setIconSize( QSize(24,24));
    fileToolBar->layout()->setSpacing(0);
#endif

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

    const QIcon remotedbIcon = QIcon::fromTheme("document-remotedb", QIcon(":/images/remotedb.png"));
    QAction *remoteDBAct = new QAction( remotedbIcon, tr("&Remote Database"), this );
    remoteDBAct->setStatusTip(tr("Connect Remote Database"));
    connect( remoteDBAct, &QAction::triggered, this, &MainWindow::remoteDB);
    fileMenu->addAction(remoteDBAct);
    fileToolBar->addAction(remoteDBAct);

    const QIcon logoutIcon = QIcon::fromTheme("document-logout", QIcon(":/images/logout.png"));
    QAction *logoutAct = new QAction( logoutIcon, tr("&Logout"), this );
    logoutAct->setShortcut(QKeySequence::Close);
    logoutAct->setStatusTip(tr("Logout current db"));
    connect( logoutAct, &QAction::triggered, this, &MainWindow::logout);
    fileMenu->addAction(logoutAct);
    fileToolBar->addAction(logoutAct);

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
    quitAct->setStatusTip( tr("Quit CertMan") );
    connect( quitAct, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction( quitAct );

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    QToolBar *toolsToolBar = addToolBar(tr("Tools"));

#ifdef Q_OS_MAC
    toolsToolBar->setIconSize( QSize(24,24));
    toolsToolBar->layout()->setSpacing(0);
#endif

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
        const QIcon configIcon = QIcon::fromTheme( "make config", QIcon(":/images/config.png"));
        QAction *configAct = new QAction( configIcon, tr( "Make Config"), this );
        configAct->setStatusTip(tr( "Make Configuration" ));
        connect( configAct, &QAction::triggered, this, &MainWindow::makeConfig );
        toolsMenu->addAction( configAct );
        toolsToolBar->addAction( configAct );


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

#ifdef Q_OS_MAC
    dataToolBar->setIconSize( QSize(24,24));
    dataToolBar->layout()->setSpacing(0);
#endif

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

    if( manApplet->isLicense() )
    {
        const QIcon setPassIcon = QIcon::fromTheme("SetPasswd", QIcon(":/images/setpass.png"));
        QAction *setPassAct = new QAction( setPassIcon, tr("&SetPasswd"), this);
        connect( setPassAct, &QAction::triggered, this, &MainWindow::setPasswd);
        getLDAPAct->setStatusTip(tr("Set PrivateKey Password"));
        dataMenu->addAction( setPassAct );
        dataToolBar->addAction( setPassAct );
    }


    if( manApplet->isPRO() )
    {
        const QIcon timeIcon = QIcon::fromTheme("Timestamp", QIcon(":/images/timestamp.png"));
        QAction *tspAct = new QAction( timeIcon, tr("&TSP"), this);
        connect( tspAct, &QAction::triggered, this, &MainWindow::tsp);
        tspAct->setStatusTip(tr("TimeStampProtocol Service"));
        dataMenu->addAction( tspAct );
        dataToolBar->addAction( tspAct );
    }


    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QToolBar *helpToolBar = addToolBar(tr("Help"));

#ifdef Q_OS_MAC
    helpToolBar->setIconSize( QSize(24,24));
    helpToolBar->layout()->setSpacing(0);
#endif

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
    settingsAct->setStatusTip(tr("Settings CertMan"));
    helpMenu->addAction( settingsAct );
    helpToolBar->addAction( settingsAct );

    if( manApplet->isLicense() )
    {
        const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
        QAction *clearAct = new QAction( clearIcon, tr("&Clear Log"), this );
        connect( clearAct, &QAction::triggered, this, &MainWindow::clearLog );
        clearAct->setStatusTip(tr("clear information and log"));
        helpMenu->addAction( clearAct );
        helpToolBar->addAction( clearAct );
    }

    const QIcon lcnIcon = QIcon::fromTheme("berview-license", QIcon(":/images/license.png"));
    QAction *lcnAct = new QAction( lcnIcon, tr("License Information"), this);
    connect( lcnAct, &QAction::triggered, this, &MainWindow::licenseInfo);
    helpMenu->addAction( lcnAct );
    lcnAct->setStatusTip(tr("License Information"));

    const QIcon certManIcon = QIcon::fromTheme("certman", QIcon(":/images/certman.png"));

    QAction *bugIssueAct = new QAction( certManIcon, tr("Bug or Issue Report"), this);
    connect( bugIssueAct, &QAction::triggered, this, &MainWindow::bugIssueReport);
    helpMenu->addAction( bugIssueAct );
    bugIssueAct->setStatusTip(tr("Bug or Issue Report"));

    QAction *qnaAct = new QAction( certManIcon, tr("Q and A"), this);
    connect( qnaAct, &QAction::triggered, this, &MainWindow::qnaDiscussion);
    helpMenu->addAction( qnaAct );
    qnaAct->setStatusTip(tr("Question and Answer"));

    QAction *aboutAct = new QAction( certManIcon, tr("&About CertMan"), this);
    connect( aboutAct, &QAction::triggered, this, &MainWindow::about);
    helpMenu->addAction( aboutAct );
    helpToolBar->addAction( aboutAct );
    aboutAct->setStatusTip(tr("About CertMan"));

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
    info_text_->clear();
    log_text_->clear();

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

    QList<QTableWidgetItem *>list = right_table_->selectedItems();
    if( list.size() > 1 )
    {
        right_table_->selectRow( list.at(0)->row() );
    }

    QMenu menu(this);

    ManTreeItem* treeItem = currentTreeItem();

    if( right_type_ == RightType::TYPE_CERTIFICATE)
    {
        if( treeItem->getType() != CM_ITEM_TYPE_IMPORT_CERT )
        {
            menu.addAction( tr( "Export PFX"), this, &MainWindow::exportPFX );
            menu.addAction( tr("Revoke Certificate"), this, &MainWindow::revokeCertificate );
            menu.addAction( tr( "Publish Certificate" ), this, &MainWindow::publishLDAP );
            menu.addAction( tr("Status Certificate"), this, &MainWindow::certStatus );
            menu.addAction( tr( "Renew Certificate"), this, &MainWindow::renewCert );
        }

        menu.addAction( tr("Export Certificate"), this, &MainWindow::exportCertificate );
        menu.addAction( tr( "View Certificate"), this, &MainWindow::viewCertificate );
        menu.addAction( tr("Delete Certificate" ), this, &MainWindow::deleteCertificate );


        if( manApplet->isPRO() )
        {
#ifdef USE_OCSP
            menu.addAction( tr("Check OCSP"), this, &MainWindow::checkOCSP );
#endif

#ifdef USE_CMP
            menu.addAction( tr("UpdateCMP"), this, &MainWindow::updateCMP );
            menu.addAction( tr("RevokeCMP"), this, &MainWindow::revokeCMP );
#endif
            menu.addAction( tr("StatusByReg"), this, &MainWindow::statusByReg );
            menu.addAction( tr("RevokeByReg"), this, &MainWindow::revokeByReg );
#ifdef USE_SCEP
            menu.addAction( tr( "RenewSCEP" ), this, &MainWindow::renewSCEP );
            menu.addAction( tr( "getCRLSCEP"), this, &MainWindow::getCRLSCEP );
#endif
        }
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        if( treeItem->getType() != CM_ITEM_TYPE_IMPORT_CRL )
        {
            menu.addAction( tr( "Verify CRL" ), this, &MainWindow::verifyCRL );
            menu.addAction( tr("Publish CRL"), this, &MainWindow::publishLDAP );
        }

        menu.addAction( tr("Export CRL"), this, &MainWindow::exportCRL );
        menu.addAction( tr("View CRL"), this, &MainWindow::viewCRL );
        menu.addAction( tr("Delete CRL"), this, &MainWindow::deleteCRL );
    }
    else if( right_type_ == RightType::TYPE_KEYPAIR )
    {
        menu.addAction(tr("Export PublicKey"), this, &MainWindow::exportPubKey );
        menu.addAction(tr("Export PrivateKey"), this, &MainWindow::exportPriKey );
        menu.addAction(tr("Export EncryptedPrivate"), this, &MainWindow::exportEncPriKey );
        menu.addAction(tr("Delete KeyPair"), this, &MainWindow::deleteKeyPair);
        menu.addAction(tr("View PrivateKey"), this, &MainWindow::viewPriKey );

        QTableWidgetItem* useitem = right_table_->item( row, 5 );
        if( useitem->text() == "NotUsed" )
            menu.addAction(tr("Make Request"), this, &MainWindow::makeRequestSetKeyName );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        menu.addAction(tr("Export Request"), this, &MainWindow::exportRequest );
        menu.addAction(tr("Delete Request"), this, &MainWindow::deleteRequest );
        menu.addAction(tr("Import CSR"), this, &MainWindow::importCSR );
        menu.addAction(tr("View CSR"), this, &MainWindow::viewCSR );

        QTableWidgetItem* useitem = right_table_->item( row, 5 );
        if( useitem->text() == "NotUsed" )
            menu.addAction(tr("Make Certificate"), this, &MainWindow::makeCertificate );

        if( manApplet->isPRO() )
        {
#ifdef USE_SCEP
            menu.addAction(tr("Issue SCEP"), this, &MainWindow::issueSCEP );
#endif
        }
    }
    else if( right_type_ == RightType::TYPE_CERT_PROFILE )
    {
        menu.addAction(tr("Delete CertProfile"), this, &MainWindow::deleteCertProfile );
        menu.addAction(tr("Edit CertProfile" ), this, &MainWindow::editCertProfile );
        menu.addAction(tr("Copy CertProfile"), this, &MainWindow::copyCertProfile );
    }
    else if( right_type_ == RightType::TYPE_CRL_PROFILE )
    {
        menu.addAction(tr("Delete CRLProfile"), this, &MainWindow::deleteCRLProfile );
        menu.addAction(tr("Edit CRLProfile"), this, &MainWindow::editCRLProfile );
        menu.addAction(tr("Copy CRLProfile"), this, &MainWindow::copyCRLProfile );
    }
    else if( right_type_ == RightType::TYPE_ADMIN )
    {
        menu.addAction(tr("Edit Admin"), this, &MainWindow::editAdmin );
    }
    else if( right_type_ == RightType::TYPE_CONFIG )
    {
        menu.addAction(tr("Edit Config"), this, &MainWindow::editConfig );
        menu.addAction(tr("Delete Config"), this, &MainWindow::deleteConfig );
    }
    else if( right_type_ == RightType::TYPE_USER )
    {
        menu.addAction(tr("Delete User"), this, &MainWindow::deleteUser );

        if( manApplet->isPRO() )
        {
#ifdef USE_CMP
            menu.addAction(tr("Issue CMP"), this, &MainWindow::issueCMP );
#endif
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

    ManTreeItem *pTopItem = new ManTreeItem( QString( tr("CertMan") ) );
    pTopItem->setIcon(QIcon(":/images/man.png"));
    pRootItem->insertRow( 0, pTopItem );

    ManTreeItem *pKeyPairItem = new ManTreeItem( QString( tr("KeyPair")) );
    pKeyPairItem->setIcon(QIcon(":/images/key_reg.png"));
    pKeyPairItem->setType( CM_ITEM_TYPE_KEYPAIR );
    pTopItem->appendRow( pKeyPairItem );

    ManTreeItem *pCSRItem = new ManTreeItem( QString( tr("Request")));
    pCSRItem->setIcon(QIcon(":/images/csr.png"));
    pCSRItem->setType( CM_ITEM_TYPE_REQUEST );
    pTopItem->appendRow( pCSRItem );

    if( manApplet->isPRO() )
    {
        ManTreeItem *pAdminItem = new ManTreeItem( QString(tr("Admin")) );
        pAdminItem->setIcon(QIcon(":/images/admin.png"));
        pAdminItem->setType( CM_ITEM_TYPE_ADMIN );
        pTopItem->appendRow( pAdminItem );

        ManTreeItem *pConfigItem = new ManTreeItem( QString(tr("Config")));
        pConfigItem->setIcon(QIcon(":/images/config.png"));
        pConfigItem->setType( CM_ITEM_TYPE_CONFIG );
        pTopItem->appendRow( pConfigItem );

        ManTreeItem *pUserItem = new ManTreeItem( QString(tr("User")) );
        pUserItem->setIcon(QIcon(":/images/user.png"));
        pUserItem->setType( CM_ITEM_TYPE_USER );
        pTopItem->appendRow( pUserItem );

        ManTreeItem *pRegSignerItem = new ManTreeItem( QString(tr("REGSigner")) );
        pRegSignerItem->setIcon(QIcon(":/images/reg_signer.png"));
        pRegSignerItem->setType( CM_ITEM_TYPE_REG_SIGNER );
        pTopItem->appendRow( pRegSignerItem );

        ManTreeItem *pOCSPSignerItem = new ManTreeItem( QString(tr("OCSPSigner")) );
        pOCSPSignerItem->setIcon(QIcon(":/images/ocsp_signer.png"));
        pOCSPSignerItem->setType( CM_ITEM_TYPE_OCSP_SIGNER );
        pTopItem->appendRow( pOCSPSignerItem );
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
    pRootCAItem->setIcon( QIcon(":/images/cert.png") );
    pRootCAItem->setType(CM_ITEM_TYPE_ROOTCA);
    pRootCAItem->setDataNum(-1);
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
        ManTreeItem *pKMSItem = new ManTreeItem( QString( tr("KMS") ));
        pKMSItem->setIcon(QIcon(":/images/kms.png"));
        pKMSItem->setType( CM_ITEM_TYPE_KMS );
        pTopItem->appendRow( pKMSItem );

        ManTreeItem *pTSPItem = new ManTreeItem( QString( tr("TSP") ));
        pTSPItem->setIcon(QIcon(":/images/timestamp.png"));
        pTSPItem->setType( CM_ITEM_TYPE_TSP );
        pTopItem->appendRow( pTSPItem );

        ManTreeItem *pStatisticsItem = new ManTreeItem( QString( tr("Statistics") ));
        pStatisticsItem->setIcon(QIcon(":/images/statistics.png"));
        pStatisticsItem->setType( CM_ITEM_TYPE_STATISTICS );
        pTopItem->appendRow( pStatisticsItem );

        ManTreeItem *pAuditItem = new ManTreeItem( QString( tr("Audit")) );
        pAuditItem->setIcon( QIcon(":/images/audit.png"));
        pAuditItem->setType( CM_ITEM_TYPE_AUDIT );
        pTopItem->appendRow( pAuditItem );
    }


    QModelIndex ri = left_model_->index(0,0);
    left_tree_->expand(ri);

//    expandItem( pRootCAItem );
}

void MainWindow::newFile()
{
    BIN binDB = {0,0};
    QString strFilter = "";

    if( manApplet->dbMgr()->isOpen() )
    {
        manApplet->warningBox( tr("Database has already openend"), this );
        return;
    }

    SetPassDlg setPassDlg;

    if( manApplet->isLicense() )
    {
        if( setPassDlg.exec() != QDialog::Accepted )
            return;
    }

    QFile resFile( ":/certman.db" );
    resFile.open(QIODevice::ReadOnly);
    QByteArray data = resFile.readAll();
    resFile.close();


    QString strPath = manApplet->getDBPath();
    QString strType = QObject::tr("DB Files (*.db *db3 *.xdb);;All Files(*.*)");
    QString selectedFilter;
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString fileName = QFileDialog::getSaveFileName( this,
                                                     tr("Save As ..."),
                                                     strPath,
                                                     strType,
                                                     &selectedFilter,
                                                     options );

    if( fileName.length() < 1 )
    {
        return;
    }

    JS_BIN_set( &binDB, (unsigned char *)data.data(), data.size() );
    JS_BIN_fileWrite( &binDB, fileName.toLocal8Bit().toStdString().c_str() );
    JS_BIN_reset(&binDB);

    manApplet->dbMgr()->close();
    int ret = manApplet->dbMgr()->open(fileName);

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database"), this );
        return;
    }

    if( manApplet->isLicense() && setPassDlg.usePasswd() )
    {
        QString strPass = setPassDlg.getPasswd();
        ConfigRec config;
        QString strHMAC = getPasswdHMAC( strPass );

        config.setKind( JS_GEN_KIND_CERTMAN );
        config.setName( "Passwd" );
        config.setValue( strHMAC );

        manApplet->dbMgr()->addConfigRec( config );
        manApplet->setPasswdKey( strPass );
    }

    manApplet->setDBPath( fileName );
    setTitle( fileName );
    createTreeMenu();
}

int MainWindow::openDB( const QString dbPath )
{
    manApplet->dbMgr()->close();
    int ret = manApplet->dbMgr()->open(dbPath);

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database"), this );
        return ret;
    }

    QString strConf;

    manApplet->dbMgr()->getConfigValue( JS_GEN_KIND_CERTMAN, "Passwd", strConf );

    if( strConf.length() > 1 )
    {
        LoginDlg loginDlg;
        if( loginDlg.exec() != QDialog::Accepted )
            return -1;

        QString strPasswd = loginDlg.getPasswd();

        QString strHMAC = getPasswdHMAC( strPasswd );

        if( strConf != strHMAC )
        {
            manApplet->warningBox( tr("Password is wrong"), this );
            manApplet->dbMgr()->close();
            return -1;
        }

        manApplet->setPasswdKey( strPasswd );
    }

    createTreeMenu();

    if( manApplet->trayIcon()->supportsMessages() )
        manApplet->trayIcon()->showMessage( "CertMan", tr("DB file is opened"), QSystemTrayIcon::Information, 10000 );

    if( ret == 0 )
    {
        setTitle( dbPath );
        adjustForCurrentFile( dbPath );
        if( manApplet->isPRO() ) addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_OPENDB, "" );
        manApplet->setDBPath( dbPath );
    }

    return ret;
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
    if( manApplet->dbMgr()->isOpen() )
    {
        manApplet->warningBox( tr("Database has already opened"), this );
        return;
    }

    QString strPath = manApplet->getDBPath();
    QString fileName = findFile( this, JS_FILE_TYPE_DB, strPath );
    if( fileName.length() < 1 ) return;

    int ret = openDB( fileName );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to open database" ), this );
        return;
    }
}

void MainWindow::remoteDB()
{
    if( manApplet->dbMgr()->isOpen() )
    {
        manApplet->warningBox( tr("Database has already opened"), this );
        return;
    }

    RemoteDBDlg remoteDBDlg;
    if( remoteDBDlg.exec() == QDialog::Accepted )
    {

    }
}

void MainWindow::openRecent()
{
    QAction *action = qobject_cast<QAction *>(sender());
    if( action )
        openDB( action->data().toString() );
}

void MainWindow::logout()
{
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr->isOpen() == false )
    {
        manApplet->warningBox( tr( "DB is not connected"), this );
    }
    else
    {
        dbMgr->close();
        removeAllRight();
        left_model_->clear();

        manApplet->messageBox( tr( "Database is closed"), this );
    }
}

void MainWindow::quit()
{
//    QCoreApplication::exit();
    manApplet->exitApp();
}


void MainWindow::newKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    NewKeyDlg newKeyDlg;
    newKeyDlg.exec();
}

void MainWindow::makeRequest()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    DBMgr* dbMgr = manApplet->dbMgr();

//    if( dbMgr->getReqCount( 0 ) <= 0 )
    if( dbMgr->getKeyPairCount(0) <= 0 )
    {
        manApplet->warningBox( tr( "There is no valid key pair"), this );
        return;
    }

    MakeReqDlg makeReqDlg;
    makeReqDlg.exec();
}

void MainWindow::makeRequestSetKeyName()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }


    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    KeyPairRec keyRec;
    manApplet->dbMgr()->getKeyPairRec( num, keyRec );

    MakeReqDlg makeReqDlg;
    makeReqDlg.setKeyName( keyRec.getName() );
    makeReqDlg.exec();
}

void MainWindow::makeCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.exec();
}

void MainWindow::makeCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }


    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.exec();
}

void MainWindow::editCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.setEdit(num);

    makeCertProfileDlg.exec();
}

void MainWindow::copyCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.loadProfile( num, true );
    makeCertProfileDlg.exec();
}

void MainWindow::editCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.setEdit(num);
    makeCRLProfileDlg.exec();
}

void MainWindow::copyCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.loadProfile( num, true );
    makeCRLProfileDlg.exec();
}

void MainWindow::makeCertificate()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( dbMgr->getCertProfileCount( JS_PKI_PROFILE_TYPE_CERT ) <= 0 )
    {
        manApplet->warningBox( tr( "There is no certificate profile"), this );
        return;
    }

    ManTreeItem *pItem = currentTreeItem();
    MakeCertDlg makeCertDlg;

    if( right_type_ == RightType::TYPE_REQUEST )
    {
        int row = right_table_->currentRow();
        QTableWidgetItem* tableItem = right_table_->item( row, 0 );

        if( tableItem )
        {
            int nReqNum = tableItem->text().toInt();
            makeCertDlg.setReqNum( nReqNum );
        }
    }


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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    if( dbMgr->getCRLProfileCount() <= 0 )
    {
        manApplet->warningBox( tr( "There is no CRL profile"), this );
        return;
    }

    ManTreeItem *pItem = currentTreeItem();
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

void MainWindow::renewCert()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ManTreeItem *pItem = currentTreeItem();

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    RenewCertDlg renewCertDlg;
    renewCertDlg.setCertNum( num );
    renewCertDlg.exec();
}

void MainWindow::revokeCertificate()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 )
    {
        manApplet->warningBox( tr( "There is no certificate to be selected" ), this );
        return;
    }

    if( right_type_ != RightType::TYPE_CERTIFICATE )
    {
        manApplet->warningBox( tr( "You have to select certificate" ), this );
        return;
    }

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    RevokeCertDlg revokeCertDlg;
    revokeCertDlg.setCertNum(num);
    revokeCertDlg.exec();
}

void MainWindow::registerUser()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    UserDlg userDlg;
    userDlg.exec();
}

void MainWindow::registerREGSigner()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    SignerDlg signerDlg;
    signerDlg.setType( SIGNER_TYPE_REG );
    signerDlg.exec();
}

void MainWindow::registerOCSPSigner()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    SignerDlg signerDlg;
    signerDlg.setType( SIGNER_TYPE_OCSP );
    signerDlg.exec();
}

void MainWindow::makeConfig()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ConfigDlg configDlg;
    configDlg.exec();
}

void MainWindow::editConfig()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    ConfigDlg configDlg;
    configDlg.setCurNum( num );
    configDlg.exec();
}

void MainWindow::deleteConfig()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this config?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->dbMgr()->delConfigRec( num );
    createRightConfigList();
}

void MainWindow::viewCertificate()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CRLInfoDlg crlInfoDlg;
    crlInfoDlg.setCRLNum( num );
    crlInfoDlg.exec();
}

void MainWindow::verifyCRL()
{
    int ret = 0;

    BIN binCRL = {0,0};
    BIN binCA = {0,0};
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CRLRec crlRec;
    CertRec caRec;

    manApplet->dbMgr()->getCRLRec( num, crlRec );
    if( crlRec.getIssuerNum() <= 0 )
    {
        manApplet->warningBox( tr( "There is no ca certificate" ), this );
        return;
    }

    manApplet->dbMgr()->getCertRec( crlRec.getIssuerNum(), caRec );

    JS_BIN_decodeHex( crlRec.getCRL().toStdString().c_str(), &binCRL );
    JS_BIN_decodeHex( caRec.getCert().toStdString().c_str(), &binCA );

    ret = JS_PKI_verifyCRL( &binCRL, &binCA );
    if( ret == 1 )
    {
        manApplet->messageBox( "Verify CRL OK", this );
    }
    else
    {
        manApplet->warningBox( QString( "Verify CRL fail: %1" ).arg(ret), this );
    }

end :
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binCA );
}

void MainWindow::viewPriKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    QTableWidgetItem* item2 = right_table_->item( row, 2 );
    int num = item->text().toInt();
    QString strAlg = item2->text();

    if( strAlg.contains( "PKCS11" ) )
    {
        manApplet->warningBox( tr("can not view PKCS11 private key:%1").arg(strAlg));
        return;
    }

    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr("can not view KMIP private key:%1").arg(strAlg));
        return;
    }

    PriKeyInfoDlg priKeyInfoDlg;
    priKeyInfoDlg.setKeyNum( num );
    priKeyInfoDlg.exec();
}

void MainWindow::viewCSR()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CSRInfoDlg csrInfoDlg;
    csrInfoDlg.setCSRNum( num );
    csrInfoDlg.exec();
}

void MainWindow::importData()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ImportDlg importDlg;
    importDlg.setType(IMPORT_TYPE_PRIKEY);
    importDlg.exec();
}

void MainWindow::importCert()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ImportDlg importDlg;
    importDlg.setType(IMPORT_TYPE_CERT);
    importDlg.exec();
}

void MainWindow::importCRL()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ImportDlg importDlg;
    importDlg.setType(IMPORT_TYPE_CRL);
    importDlg.exec();
}

void MainWindow::importCSR()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ImportDlg importDlg;
    importDlg.setType(IMPORT_TYPE_CSR);
    importDlg.exec();
}

void MainWindow::importPriKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ImportDlg importDlg;
    importDlg.setType(IMPORT_TYPE_PRIKEY);
    importDlg.exec();
}

void MainWindow::importEncPriKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    ImportDlg importDlg;
    importDlg.setType(IMPORT_TYPE_ENC_PRIKEY);
    importDlg.exec();
}

void MainWindow::exportPriKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    DBMgr* dbMgr = manApplet->dbMgr();
    KeyPairRec keyPair;

    dbMgr->getKeyPairRec( num, keyPair );
    QString strAlg = keyPair.getAlg();

    if( strAlg.contains( "PKCS11" ) )
    {
        manApplet->warningBox( tr("can not read PKCS11 private key:%1").arg(strAlg));
        return;
    }

    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr("can not read KMIP private key:%1").arg(strAlg));
        return;
    }

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_PRIKEY );
    exportDlg.exec();
}

void MainWindow::exportEncPriKey()
{   
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    DBMgr* dbMgr = manApplet->dbMgr();
    KeyPairRec keyPair;

    dbMgr->getKeyPairRec( num, keyPair );
    QString strAlg = keyPair.getAlg();

    if( strAlg.contains( "PKCS11" ) )
    {
        manApplet->warningBox( tr("can not read PKCS11 private key:%1").arg(strAlg));
        return;
    }

    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr("can not read KMIP private key:%1").arg(strAlg));
        return;
    }

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_ENC_PRIKEY );
    exportDlg.exec();
}

void MainWindow::exportPubKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CertRec certRec;
    KeyPairRec keyPair;

    DBMgr* dbMgr = manApplet->dbMgr();
    dbMgr->getCertRec( num, certRec );

    dbMgr->getKeyPairRec( certRec.getKeyNum(), keyPair );
    QString strAlg = keyPair.getAlg();

    if( strAlg.contains( "PKCS11" ) )
    {
        manApplet->warningBox( tr("can not read PKCS11 private key:%1").arg(strAlg));
        return;
    }

    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr("can not read KMIP private key:%1").arg(strAlg));
        return;
    }

    ExportDlg exportDlg;
    exportDlg.setDataNum( num );
    exportDlg.setExportType( EXPORT_TYPE_PFX );
    exportDlg.exec();
}

void MainWindow::setPasswd()
{
    if( manApplet->dbMgr()->isOpen() == false )
    {
        manApplet->warningBox( tr( "Database is not opened" ), this );
        return;
    }

    if( manApplet->isPasswd() == true )
    {
        manApplet->warningBox( tr( "The PrivateKeys are already encrypted."), this );
        return;
    }

    if( manApplet->isLicense() == false )
    {
        manApplet->warningBox( tr( "There is no license"), this );
        return;
    }

    int nKeyCount = manApplet->dbMgr()->getKeyPairCountAll();
    if( nKeyCount > 0 )
    {
        manApplet->warningBox( tr( "KeyPair has to be empty"), this );
        return;
    }

    SetPassDlg setPassDlg;
    setPassDlg.mUsePasswdCheck->setEnabled(false);

    if( setPassDlg.exec() != QDialog::Accepted )
        return;

    QString strPass = setPassDlg.getPasswd();
    ConfigRec config;
    QString strHMAC = getPasswdHMAC( strPass );

    config.setKind( JS_GEN_KIND_CERTMAN );
    config.setName( "Passwd" );
    config.setValue( strHMAC );

    manApplet->dbMgr()->addConfigRec( config );
    manApplet->setPasswdKey( strPass );
}

void MainWindow::publishLDAP()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 )
    {
        manApplet->warningBox( tr( "A item is not selected"), this );
        return;
    }

    if( right_type_ != RightType::TYPE_CERTIFICATE && right_type_ != RightType::TYPE_CRL )
    {
        manApplet->warningBox(tr("Invalid data type"), this );
        return;
    }

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    PubLDAPDlg pubLDAPDlg;
    pubLDAPDlg.setDataNum( num );
    pubLDAPDlg.setDataType( right_type_ );
    pubLDAPDlg.exec();
}

void MainWindow::getLDAP()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this certificate profile?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->dbMgr()->delCertProfile( num );
    manApplet->dbMgr()->delCertProfileExtensionList( num );
    createRightCertProfileList();
}

void MainWindow::deleteCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this CRL profile?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->dbMgr()->delCRLProfile( num );
    manApplet->dbMgr()->delCRLProfileExtensionList( num );
    createRightCRLProfileList();
}

void MainWindow::deleteCertificate()
{
    DBMgr* dbMgr = manApplet->dbMgr();

    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this certificate?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    CertRec cert;
    dbMgr->getCertRec( num, cert );

    if( cert.isCA() )
    {
        int nCertCnt = dbMgr->getCertSearchCount( num );
        manApplet->log( QString("Issued Cert Cnt : %1").arg( nCertCnt ));
        int nCRLCnt = dbMgr->getCRLSearchCount( num );
        manApplet->log( QString( "Issued CRL Cnt : %1" ).arg( nCRLCnt ));

        if( nCertCnt > 0 || nCRLCnt > 0 )
        {
            manApplet->warningBox( tr("The cert have certificates or crls to be issued"), this );
            return;
        }

        if( cert.isSelf() )
        {
            /* Remove RootCA TreeItem */
            if( root_ca_ != NULL && root_ca_->hasChildren() )
            {
                int nRow = root_ca_->rowCount();
                for( int i = 0; i < nRow; i++ )
                {
                    ManTreeItem *child = (ManTreeItem *)root_ca_->child( i );
                    if( child->getDataNum() == num )
                    {
                        root_ca_->removeRow( i );
                        break;
                    }
                }
            }
        }
    }

    dbMgr->delCertRec( num );
    manApplet->log( QString( "CertNum : %1 is deleted").arg( num ));

    createRightCertList( cert.getIssuerNum() );
}

void MainWindow::deleteCRL()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this CRL?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row , 0 );

    int num = item->text().toInt();

    CRLRec crl;

    manApplet->dbMgr()->getCRLRec( num, crl );
    manApplet->dbMgr()->delCRLRec( num );
    manApplet->log( QString("CRLNum:%1 is deleted").arg(num));

    createRightCRLList( crl.getIssuerNum() );
}

void MainWindow::deleteKeyPair()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this key pair?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    int nReqCnt = manApplet->dbMgr()->getKeyCountReq( num );
    manApplet->log( QString( "KeyNum: %1 ReqCount: %2").arg( num ).arg( nReqCnt ));
    int nCertCnt = manApplet->dbMgr()->getKeyCountCert( num );
    manApplet->log( QString( "KeyNum: %1 CertCount: %2").arg( num ).arg( nCertCnt ));

    if( nReqCnt > 0 || nCertCnt > 0)
    {
        manApplet->warningBox( tr( "The KeyNum(%1) has already used in Req or Cert").arg(num), this );
        return;
    }

    manApplet->dbMgr()->delKeyPairRec( num );
    manApplet->log( QString("KeyNum:%1 is deleted").arg(num));

    createRightKeyPairList();
}

void MainWindow::deleteRequest()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this request?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    manApplet->dbMgr()->delReqRec( num );
    manApplet->log( QString("ReqNum:%1 is deleted").arg(num));

    createRightRequestList();
}

void MainWindow::deleteUser()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this user?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    manApplet->dbMgr()->delUserRec( num );
    manApplet->log( QString("UserNum:%1 is deleted").arg(num));

    createRightUserList();
}

void MainWindow::deleteSigner()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this signer?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    SignerRec signer;
    manApplet->dbMgr()->getSignerRec( num, signer );
    manApplet->dbMgr()->delSignerRec( num );

    createRightSignerList( signer.getType() );
}

void MainWindow::registerAdmin()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

    AdminDlg adminDlg;
    adminDlg.exec();
}

void MainWindow::editAdmin()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("You have to open database"), this );
        return;
    }

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

void MainWindow::logView( bool bShow )
{
    if( bShow == true )
    {
        if( text_tab_->count() <= 1 )
            text_tab_->addTab( log_text_, tr("log") );
    }
    else
    {
        if( text_tab_->count() == 2 )
            text_tab_->removeTab(1);
    }
}

void MainWindow::log( const QString strLog, QColor cr )
{
    if( text_tab_->count() <= 1 ) return;

    QTextCursor cursor = log_text_->textCursor();
//    cursor.movePosition( QTextCursor::End );

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    cursor.insertText( "\n" );

    log_text_->setTextCursor( cursor );
    log_text_->repaint();
}

void MainWindow::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}

void MainWindow::info( const QString strLog, QColor cr )
{
    QTextCursor cursor = info_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );

    info_text_->setTextCursor( cursor );
    info_text_->repaint();
}

void MainWindow::infoClear()
{
    info_text_->clear();
}

void MainWindow::infoCursorTop()
{
    info_text_->moveCursor(QTextCursor::Start);
}

void MainWindow::treeMenuClick(QModelIndex index )
{
    int nType = -1;
    int nNum = -1;

    ManTreeItem *pItem = (ManTreeItem *)left_model_->itemFromIndex(index);

    if( pItem == NULL ) return;

    nNum = pItem->getDataNum();
    nType = pItem->getType();


    fflush( stdout );

    search_form_->setCurPage(0);
    search_form_->setLeftNum( nNum );
    search_form_->setLeftType( nType );

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
        infoKeyPair( nSeq );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        infoRequest( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CERTIFICATE )
    {
        infoCertificate( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        infoCRL( nSeq );
    }
    else if( right_type_ == RightType::TYPE_REVOKE )
    {
        infoRevoke( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CERT_PROFILE )
    {
        infoCertProfile( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CRL_PROFILE )
    {
        infoCRLProfile( nSeq );
    }
    else if( right_type_ == RightType::TYPE_USER )
    {
        infoUser( nSeq );
    }
    else if( right_type_ == RightType::TYPE_ADMIN )
    {
        infoAdmin( nSeq );
    }
    else if( right_type_ == RightType::TYPE_CONFIG )
    {
        infoConfig( nSeq );
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        infoSigner( nSeq );
    }
    else if( right_type_ == RightType::TYPE_KMS )
    {
        infoKMS( nSeq );
    }
    else if( right_type_ == RightType::TYPE_STATISTICS )
    {
        infoStatistics();
    }
    else if( right_type_ == RightType::TYPE_AUDIT )
    {
        infoAudit( nSeq );
    }
    else if( right_type_ == RightType::TYPE_TSP )
    {
        infoTSP( nSeq );
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

#ifdef USE_CMP

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
   manApplet->dbMgr()->getUserRec( num, userRec );

   if( userRec.getAuthCode().length() < 1 )
   {
       manApplet->warningBox( tr( "AuthNum is empty" ), this );
       return;
   }

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

   writeKeyPairDB( manApplet->dbMgr(), userRec.getName().toStdString().c_str(), &binPub, &binPri  );

   ret = JS_CMP_clientIR( strURL.toStdString().c_str(), pTrustList, strDN.toStdString().c_str(), &binRefNum, &binAuthCode, &binPri, 0, &binCert );
   if( ret != 0 ) goto end;

   writeCertDB( manApplet->dbMgr(), &binCert );

/*
   ret = JS_CMP_clientIssueCertConf( strURL.toStdString().c_str(), pTrustList, &binCert, &binRefNum, &binAuthCode );
   if( ret != 0 ) goto end;
*/

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
   manApplet->dbMgr()->getCertRec( num, certRec );

   if( certRec.getKeyNum() <= 0 )
   {
       manApplet->warningBox( tr("KeyPair information is not set"), this );
       return;
   }

   KeyPairRec keyPair;
   manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );

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

   writeKeyPairDB( manApplet->dbMgr(), certRec.getSubjectDN().toStdString().c_str(), &binPub, &binNewPri );

   ret = JS_CMP_clientKUR( strURL.toStdString().c_str(), pTrustList, &binCACert, &binCert, &binPri, &binNewPri, 0, &binNewCert );
   if( ret != 0 ) goto end;

   writeCertDB( manApplet->dbMgr(), &binNewCert );

   /*
   ret = JS_CMP_clientUpdateCertConf( strURL.toStdString().c_str(), pTrustList, &binNewCert, &binNewPri );
   if( ret != 0 ) goto end;
   */

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
   manApplet->dbMgr()->getCertRec( num, certRec );
   KeyPairRec keyPair;

   if( certRec.getKeyNum() <= 0 )
   {
       manApplet->warningBox(tr("KeyPair information is not set"), this );
       return;
   }

   manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );

   JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
   JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri );

   QString strURL = manApplet->settingsMgr()->CMPURI();
   strURL += "/CMP";
   QString strCAPath = manApplet->settingsMgr()->CMPCACertPath();

   JS_BIN_fileRead( strCAPath.toLocal8Bit().toStdString().c_str(), &binCACert );

   ret = JS_CMP_clientRR( strURL.toStdString().c_str(), pTrustList, &binCACert, &binCert, &binPri, nReason );

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
   JS_BIN_reset( &binCACert );

   if( pTrustList ) JS_BIN_resetList( &pTrustList );
}

#endif

void MainWindow::verifyAudit()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    AuditRec audit;

    manApplet->dbMgr()->getAuditRec( num, audit );

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
    manApplet->dbMgr()->getTSPRec( num, tspRec );
    JS_BIN_decodeHex( tspRec.getData().toStdString().c_str(), &binTS );


    SettingsMgr *smgr = manApplet->settingsMgr();
    if( smgr )
    {
        if( smgr->TSPUse() )
        {
            JS_BIN_fileRead( smgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binCert );
        }
    }

    ret = JS_PKCS7_verifySignedData( &binTS, &binCert, &binData );
    QString strVerify = QString( "Verify val:%1" ).arg( ret );

    manApplet->messageBox( strVerify, this );

    JS_BIN_reset( &binTS );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binData );
}

#ifdef USE_SCEP
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
    manApplet->dbMgr()->getReqRec( num, req );
    KeyPairRec keyPair;
    manApplet->dbMgr()->getKeyPairRec( req.getKeyNum(), keyPair );

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
        elog( QString( "fail to request Get [%1:%2]" ).arg(nRet).arg(nStatus));
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
        elog( QString("fail to make PKIReq : %1").arg( nRet ));
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
        elog(QString( "fail to request Post [%1:%2]" ).arg( nRet ).arg( nStatus ));
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
        elog(QString("fail to parse CertRsp : %1").arg( nRet ));
        manApplet->warningBox( "fail to parse CertRsp", this );
        goto end;
    }

//    JS_BIN_fileWrite( &binSignedData, "D:/jsca/res_signeddata.ber" );

    nRet = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNewCert );
    if( nRet != 0 )
    {
        elog(QString("fail to get sign certificate in reply: %1").arg( nRet ));
        manApplet->warningBox( "fail to get sign certificate in reply", this );
        goto end;
    }

    writeCertDB( manApplet->dbMgr(), &binNewCert );

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

    manApplet->dbMgr()->getCertRec( num, certRec );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( certRec.getKeyNum() < 0 )
    {
        manApplet->warningBox( tr( "The certificate has not keypair in this tool"), this );
        goto end;
    }

    manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );
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
    {
        ret = JS_PKI_RSAGenKeyPair( nOption, 63357, &binNPub, &binNPri );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        ret = JS_PKI_ECCGenKeyPair( JS_PKI_getSNFromNid( nOption ), &binNPub, &binNPri );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to generate keypair"), this );
        goto end;
    }

    nKeyNum = writeKeyPairDB( manApplet->dbMgr(), sCertInfo.pSubjectName, &binNPub, &binNPri );

    ret = JS_PKI_makeCSR( nKeyType, "SHA256", sCertInfo.pSubjectName, pChallengePass, &binNPri, NULL, &binCSR );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to make csr"), this );
        goto end;
    }

    writeCSRDB( manApplet->dbMgr(), nKeyNum, "SCEP Update", sCertInfo.pSubjectName, "SHA256", &binCSR );

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
        elog(QString("fail to request Get [%1:%2]").arg(ret).arg(nStatus));
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
        elog(QString("fail to make PKIReq : %1").arg( ret ));
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
        elog(QString("fail to request Post [%1:%2]").arg(ret).arg(nStatus));
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
        elog(QString("fail to parse CertRsp : %1").arg(ret));
        manApplet->warningBox( "fail to parse CertRsp", this );
        goto end;
    }

    ret = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNCert );
    if( ret != 0 )
    {
        elog(QString("fail to get sign certificate in reply: %1").arg(ret));
        manApplet->warningBox( "fail to get sign certificate in reply", this );
        goto end;
    }

    writeCertDB( manApplet->dbMgr(), &binNCert );

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

    manApplet->dbMgr()->getCertRec( num, certRec );

    if( certRec.getKeyNum() < 0 )
    {
        manApplet->warningBox( tr( "The certificate has not keypair in this tool"), this );
        goto end;
    }

    manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );
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
        elog(QString("fail to request Get [%1:%2]").arg(ret).arg( nStatus ));
        manApplet->warningBox( "fail to request Get", this );
        goto end;
    }

    ret = JS_SCEP_makeGetCRL( &binCert, &binPri, &binCert, &binCACert, &binSenderNonce, pTransID, &binReq );


    if( ret != 0 )
    {
        elog(QString("fail to make getCRL : %1").arg(ret));
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
        elog(QString("fail to request Post [%1:%2]").arg(ret).arg(nStatus));
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
        elog(QString("fail to parse CertRsp : %1").arg(ret));
        manApplet->warningBox( "fail to parse CertRsp", this );
        goto end;
    }

    ret = JS_SCEP_getCRL( &binSignedData, &binCRL );
    if( ret != 0 )
    {
        elog(QString("fail to get crl in reply: %1").arg(ret));
        manApplet->warningBox( "fail to get crl in reply", this );
        goto end;
    }

    writeCRLDB( manApplet->dbMgr(), &binCRL );

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

#endif

void MainWindow::clearLog()
{
    log_text_->clear();
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
    manApplet->dbMgr()->getCACertList( nIssuerNum, certList );

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec certRec = certList.at(i);

        ManTreeItem *pCAItem = new ManTreeItem( certRec.getSubjectDN() );
        pCAItem->setType( CM_ITEM_TYPE_CA );
        pCAItem->setDataNum( certRec.getNum() );
        pCAItem->setIcon( QIcon(":/images/ca.png"));
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

        ManTreeItem *pSubCAItem = new ManTreeItem( QString(tr("CA")));
        pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
        pSubCAItem->setIcon(QIcon(":/images/ca.png"));
        pSubCAItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pSubCAItem );

//        left_tree_->expand( pCAItem->index() );
    }

    left_tree_->expand( item->index() );
}

void MainWindow::licenseInfo()
{
    LCNInfoDlg lcnInfoDlg;
    if( lcnInfoDlg.exec() == QDialog::Accepted )
    {
        if( manApplet->yesOrNoBox(tr("You have changed license. Restart to apply it?"), this, true))
            manApplet->restartApp();
    }
}

void MainWindow::bugIssueReport()
{
    QString link = "https://github.com/jykim74/CertMan/issues/new";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::qnaDiscussion()
{
    QString link = "https://github.com/jykim74/CertMan/discussions/new?category=q-a";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::addRootCA( CertRec& certRec )
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

    manApplet->dbMgr()->getCertRec( num, certRec );

    if( certRec.getNum() <= 0 )
    {
        manApplet->warningBox( tr("fail to get certificate information"), this );
        return;
    }

    if( certRec.getStatus() > 0 )
    {
        manApplet->dbMgr()->getRevokeRecByCertNum( certRec.getNum(), revokeRec );
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

#ifdef USE_OCSP

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
    BIN binSrvCert = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binSignerCert = {0,0};
    BIN binSignerPri = {0,0};


    CertRec caRec;
    CertRec certRec;

    JCertIDInfo sIDInfo;
    JCertStatusInfo sStatusInfo;

    QString strURL;
    QString strOCSPSrvCert;
    QString strStatus;

    memset( &sIDInfo, 0x00, sizeof(sIDInfo));
    memset( &sStatusInfo, 0x00, sizeof(sStatusInfo));

    manApplet->dbMgr()->getCertRec( num, certRec );
    manApplet->dbMgr()->getCertRec( certRec.getIssuerNum(), caRec );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    JS_BIN_decodeHex( caRec.getCert().toStdString().c_str(), &binCA );

    if( manApplet->settingsMgr()->OCSPAttachSign() == true )
    {
        QString strCertPath = manApplet->settingsMgr()->OCSPSignerCertPath();
        QString strPriPath = manApplet->settingsMgr()->OCSPSignerPriPath();

        JS_BIN_fileRead( strCertPath.toLocal8Bit().toStdString().c_str(), &binSignerCert );
        JS_BIN_fileRead( strPriPath.toLocal8Bit().toStdString().c_str(), &binSignerPri );

        ret = JS_OCSP_encodeRequest( &binCert, &binCA, "SHA1", &binSignerPri, &binSignerCert, &binReq );
    }
    else
    {
        ret = JS_OCSP_encodeRequest( &binCert, &binCA, "SHA1", NULL, NULL, &binReq );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( QString(tr("fail to encode request: %1")).arg(ret), this );
        goto end;
    }

    strURL = manApplet->settingsMgr()->OCSPURI();
    strURL += "/OCSP";
    strOCSPSrvCert = manApplet->settingsMgr()->OCSPSrvCertPath();

    JS_BIN_fileRead( strOCSPSrvCert.toLocal8Bit().toStdString().c_str(), &binSrvCert );

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/ocsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "fail to request"), this );
        goto end;
    }


    ret = JS_OCSP_decodeResponse( &binRsp, &binSrvCert, &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( QString(tr( "fail to decode respose:%1" )).arg(ret), this );
        goto end;
    }

    if( sStatusInfo.nStatus == JS_OCSP_STATUS_GOOD )
        strStatus = "GOOD";
    else if( sStatusInfo.nStatus == JS_OCSP_STATUS_UNKNOWN )
        strStatus = "UNKNOWN";
    else if( sStatusInfo.nStatus == JS_OCSP_STATUS_REVOKED )
    {
        char sDateTime[32];
        QString strReason = getRevokeReasonName( sStatusInfo.nReason );

        memset( sDateTime, 0x00, sizeof(sDateTime));
        JS_UTIL_getDateTime( sStatusInfo.nRevokedTime, sDateTime );
        strStatus = QString( "Revoked[ Reason : %1, RevokedTime : %2]" )
                .arg( strReason )
                .arg( sDateTime );
    }

    manApplet->messageBox( strStatus, this );

 end :

    JS_BIN_reset( &binCA );
    JS_BIN_reset( &binCert );
    JS_BIN_reset( &binSrvCert );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binSignerCert );
    JS_BIN_reset( &binSignerPri );

    JS_OCSP_resetCertIDInfo( &sIDInfo );
    JS_OCSP_resetCertStatusInfo( &sStatusInfo );
}

#endif

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
    UserRec user;
    manApplet->dbMgr()->getCertRec( num, cert );

    if( cert.getUserNum() <= 0 )
    {
        manApplet->warningBox( tr("There is no user" ), this );
        return;
    }

    manApplet->dbMgr()->getUserRec( cert.getUserNum(), user );

    JS_JSON_setRegCertStatusReq( &sStatusReq, "name", user.getName().toStdString().c_str() );

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

    JS_HTTP_requestPost( strURL.toStdString().c_str(), "application/json", pReq, &nStatus, &pRsp );

    JS_JSON_decodeRegCertStatusRsp( pRsp, &sStatusRsp );

    if( strcasecmp( sStatusRsp.pResCode, "0000" ) == 0 )
    {
        QString strStatus = sStatusRsp.pStatus;
        manApplet->messageBox( strStatus, this );
        ret = 0;
    }
    else
    {
        manApplet->warningBox( "fail to get certificate status by REGServer", this );
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
    UserRec user;

    manApplet->dbMgr()->getCertRec( num, cert );

    if( cert.getUserNum() <= 0 )
    {
        manApplet->warningBox( tr("There is no user" ), this );
        return;
    }

    manApplet->dbMgr()->getUserRec( cert.getUserNum(), user );

    strURL = mgr->REGURI();
    strURL += "/certrevoke";

    JS_JSON_setRegCertRevokeReq( &sRevokeReq, "name", cert.getSubjectDN().toStdString().c_str(), "1" );

    JS_JSON_encodeRegCertRevokeReq( &sRevokeReq, &pReq );

    JS_HTTP_requestPost( strURL.toStdString().c_str(), "application/json", pReq, &nStatus, &pRsp );

    JS_JSON_decodeRegRsp( pRsp, &sRevokeRsp );

    if( strcasecmp( sRevokeRsp.pResCode, "0000" ) == 0 )
    {
        manApplet->messageBox( tr("Revoke is success"), this );
        ret = 0;
    }
    else
    {
        manApplet->warningBox( "fail to revoke certificate by REGServer", this );
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
    else if( nType == CM_ITEM_TYPE_CONFIG )
        createRightConfigList();
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
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_KEYPAIR;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

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
        nTotalCount = manApplet->dbMgr()->getKeyPairSearchCount( -1,  strTarget, strWord );
        manApplet->dbMgr()->getKeyPairList( -1, strTarget, strWord, nOffset, nLimit, keyPairList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getKeyPairCount( -1 );
        manApplet->dbMgr()->getKeyPairList( -1, nOffset, nLimit, keyPairList );
    }

    right_table_->setColumnWidth( 0, 60 ); // Number
    right_table_->setColumnWidth( 1, 140 ); // RegTime
    right_table_->setColumnWidth( 2, 80 );
    right_table_->setColumnWidth( 3, 300 );
    right_table_->setColumnWidth( 4, 80 );
    right_table_->setColumnWidth( 5, 40 );

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        char sRegTime[64];
        KeyPairRec keyPairRec = keyPairList.at(i);

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg(keyPairRec.getNum() ));
        seq->setIcon( QIcon(":/images/key_reg.png" ));

        QTableWidgetItem *item = new QTableWidgetItem( keyPairRec.getName() );


        JS_UTIL_getDateTime( keyPairRec.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg(sRegTime)));
        right_table_->setItem( i, 2, new QTableWidgetItem( keyPairRec.getAlg()));
        right_table_->setItem( i, 3, item );
        right_table_->setItem(i, 4, new QTableWidgetItem( keyPairRec.getParam()));
        right_table_->setItem(i, 5, new QTableWidgetItem( QString("%1").arg(getRecStatusName(keyPairRec.getStatus()))));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}


void MainWindow::createRightRequestList()
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_REQUEST;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

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
        nTotalCount = manApplet->dbMgr()->getReqSearchCount( -1,  strTarget, strWord );
        manApplet->dbMgr()->getReqList( -1, strTarget, strWord, nOffset, nLimit, reqList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getReqCount( -1 );
        manApplet->dbMgr()->getReqList( -1, nOffset, nLimit, reqList );
    }

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 140 );
    right_table_->setColumnWidth( 3, 140 );
    right_table_->setColumnWidth( 4, 60 );
    right_table_->setColumnWidth( 5, 60 );

    for( int i=0; i < reqList.size(); i++ )
    {
        char sRegTime[64];
        ReqRec reqRec = reqList.at(i);

        QTableWidgetItem *item = new QTableWidgetItem( reqRec.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( reqRec.getSeq() ));
        seq->setIcon(QIcon(":/images/csr.png"));

        JS_UTIL_getDateTime( reqRec.getRegTime(), sRegTime );

        QString strKeyName = manApplet->dbMgr()->getNumName( reqRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sRegTime ) ));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strKeyName ) ));
        right_table_->setItem( i, 3, item );
        right_table_->setItem( i, 4, new QTableWidgetItem( reqRec.getHash() ));
        right_table_->setItem( i, 5, new QTableWidgetItem( QString("%1").arg( getRecStatusName(reqRec.getStatus()) )));
        right_table_->setItem( i, 6, new QTableWidgetItem( reqRec.getDN() ));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightCertProfileList()
{
    search_form_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CERT_PROFILE;

    QStringList headerList = { tr("Num"), tr("Name"), tr("Version"), tr("NotBefore"), tr("NotAfter"), tr("Hash"), tr("Type") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CertProfileRec> certProfileList;
    manApplet->dbMgr()->getCertProfileList( certProfileList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 200 );
    right_table_->setColumnWidth( 2, 60 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 60 );

    for( int i=0; i < certProfileList.size(); i++ )
    {
        CertProfileRec certProfile = certProfileList.at(i);
        QString strVersion;
        QString strNotBefore;
        QString strNotAfter;
 //       QString strDNTemplate;

        QTableWidgetItem *item = new QTableWidgetItem( certProfile.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( certProfile.getNum() ));

        if( certProfile.getType() == JS_PKI_PROFILE_TYPE_CSR )
            seq->setIcon(QIcon(":/images/csr_profile.png"));
        else
            seq->setIcon(QIcon(":/images/cert_profile.png"));

        strVersion = QString( "V%1" ).arg( certProfile.getVersion() + 1);

        if( certProfile.getNotBefore() == 0 )
        {
            strNotBefore = "GenTime";
            strNotAfter = QString( "%1 Days" ).arg( certProfile.getNotAfter() );
        }
        else if( certProfile.getNotBefore() == 1 )
        {
            strNotBefore = "GenTime";
            strNotAfter = QString( "%1 Months" ).arg( certProfile.getNotAfter() );
        }
        else if( certProfile.getNotBefore() == 2 )
        {
            strNotBefore = "GenTime";
            strNotAfter = QString( "%1 Years" ).arg( certProfile.getNotAfter() );
        }
        else
        {
            strNotBefore = getDateTime( certProfile.getNotBefore() );
            strNotAfter = getDateTime( certProfile.getNotAfter() );
        }
/*
        if( certProfile.getDNTemplate() == "#CSR" )
            strDNTemplate = "Use CSR DN";
        else
            strDNTemplate = certProfile.getDNTemplate();
*/


        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, item);
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strVersion )));
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg( strNotBefore )));
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg( strNotAfter )));
        right_table_->setItem( i, 5, new QTableWidgetItem( certProfile.getHash() ));
        right_table_->setItem( i, 6, new QTableWidgetItem( getProfileType( certProfile.getType() ) ));
    }
}

void MainWindow::createRightCRLProfileList()
{
    search_form_->hide();

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
    manApplet->dbMgr()->getCRLProfileList( crlProfileList );

    right_table_->setColumnWidth( 0, 60 );
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

        QTableWidgetItem *item = new QTableWidgetItem( crlProfile.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( crlProfile.getNum() ));
        seq->setIcon(QIcon(":/images/crl_profile.png"));

        strVersion = QString( "V%1" ).arg( crlProfile.getVersion() + 1);

        if( crlProfile.getLastUpdate() == 0 )
        {
            strLastUpdate = "GenTime";
            strNextUpdate = QString( "%1 Days" ).arg( crlProfile.getNextUpdate() );
        }
        else if( crlProfile.getLastUpdate() == 1 )
        {
            strLastUpdate = "GenTime";
            strNextUpdate = QString( "%1 Months" ).arg( crlProfile.getNextUpdate() );
        }
        else if( crlProfile.getLastUpdate() == 2 )
        {
            strLastUpdate = "GenTime";
            strNextUpdate = QString( "%1 Years" ).arg( crlProfile.getNextUpdate() );
        }
        else
        {
            strLastUpdate = getDateTime( crlProfile.getLastUpdate() );
            strNextUpdate = getDateTime( crlProfile.getNextUpdate() );
        }

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, item );
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strVersion )) );
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg( strLastUpdate )) );
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg( strNextUpdate )) );
        right_table_->setItem( i, 5, new QTableWidgetItem( crlProfile.getHash()) );
    }
}

void MainWindow::createRightCertList( int nIssuerNum, bool bIsCA )
{
    search_form_->show();
    removeAllRight();
    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    right_type_ = RightType::TYPE_CERTIFICATE;

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Key"), tr("Algorithm"), tr("SubjectDN") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QList<CertRec> certList;

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 140 );


    if( bIsCA )
    {
        if( strWord.length() > 0 )
            manApplet->dbMgr()->getCACertList( nIssuerNum, strTarget, strWord, certList );
        else
            manApplet->dbMgr()->getCACertList( nIssuerNum, certList );

        nTotalCount = certList.size();
    }
    else
    {
        if( strWord.length() > 0 )
        {
            nTotalCount = manApplet->dbMgr()->getCertSearchCount( nIssuerNum,  strTarget, strWord );
            manApplet->dbMgr()->getCertList( nIssuerNum, strTarget, strWord, nOffset, nLimit, certList );
        }
        else
        {
            nTotalCount = manApplet->dbMgr()->getCertCount( nIssuerNum );
            manApplet->dbMgr()->getCertList( nIssuerNum, nOffset, nLimit, certList );
        }
    }

    for( int i=0; i < certList.size(); i++ )
    {
        int pos = 0;
        CertRec cert = certList.at(i);
        char    sRegTime[64];



        QString strDNInfo;
        if( cert.isSelf() ) strDNInfo += "[Self]";

        if( cert.getIssuerNum() >= 0 )
            strDNInfo += QString( "[%1] " ).arg( getCertStatusSName(cert.getStatus()) );

        strDNInfo += cert.getSubjectDN();

        QTableWidgetItem *item = new QTableWidgetItem( strDNInfo );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( cert.getNum() ));

        if( cert.isCA() )
        {
            if( cert.getStatus() == JS_CERT_STATUS_REVOKE )
                seq->setIcon(QIcon(":/images/ca_revoked.png"));
            else
                seq->setIcon(QIcon(":/images/ca.png"));
        }
        else
        {
            if( cert.getStatus() == JS_CERT_STATUS_REVOKE )
                seq->setIcon(QIcon(":/images/cert_revoked.png"));
            else
                seq->setIcon(QIcon(":/images/cert.png"));
        }

        JS_UTIL_getDateTime( cert.getRegTime(), sRegTime );

        QString strKeyName;
        QString strUserName;

        if( cert.getKeyNum() >= 0 )
            strKeyName = manApplet->dbMgr()->getNumName( cert.getKeyNum(), "TB_KEY_PAIR", "NAME" );
        else
            strKeyName = "None";

        if( cert.getUserNum() > 0 )
            manApplet->dbMgr()->getNumName( cert.getUserNum(), "TB_USER", "NAME" );
        else
            strUserName = "";

        QString strAlg = cert.getSignAlg();

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, pos++, seq );
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( sRegTime ) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( strKeyName )));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( strAlg )));
        right_table_->setItem( i, pos++, item );
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightCRLList( int nIssuerNum )
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_CRL;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;
    char sRegTime[64];

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Issuer"), tr("SignAlg"), tr("CRLDP") };
    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CRLRec> crlList;

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 200 );
    right_table_->setColumnWidth( 3, 140 );


    if( strWord.length() > 0 )
    {
        nTotalCount = manApplet->dbMgr()->getCRLSearchCount( nIssuerNum,  strTarget, strWord );
        manApplet->dbMgr()->getCRLList( nIssuerNum, strTarget, strWord, nOffset, nLimit, crlList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getCRLCount( nIssuerNum );
        manApplet->dbMgr()->getCRLList( nIssuerNum, nOffset, nLimit, crlList );
    }

    for( int i=0; i < crlList.size(); i++ )
    {
        CRLRec crl = crlList.at(i);
        QString strIssuerName;

        if( crl.getIssuerNum() >= 0 )
            strIssuerName = manApplet->dbMgr()->getNumName( crl.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
        else
            strIssuerName = "None";

        QTableWidgetItem *item = new QTableWidgetItem( strIssuerName );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( crl.getNum() ));
        seq->setIcon(QIcon(":/images/crl.png"));

        JS_UTIL_getDateTime( crl.getRegTime(), sRegTime );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( sRegTime )));
        right_table_->setItem( i, 2, item );
        right_table_->setItem( i, 3, new QTableWidgetItem( crl.getSignAlg() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( crl.getCRLDP() ));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightRevokeList(int nIssuerNum)
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_REVOKE;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

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
        nTotalCount = manApplet->dbMgr()->getRevokeSearchCount( nIssuerNum,  strTarget, strWord );
        manApplet->dbMgr()->getRevokeList( nIssuerNum, strTarget, strWord, nOffset, nLimit, revokeList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getRevokeCount( nIssuerNum );
        manApplet->dbMgr()->getRevokeList( nIssuerNum, nOffset, nLimit, revokeList );
    }

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 120 );
    right_table_->setColumnWidth( 2, 120 );
    right_table_->setColumnWidth( 3, 60 );
    right_table_->setColumnWidth( 4, 140 );
    right_table_->setColumnWidth( 5, 120 );

    for( int i=0; i < revokeList.size(); i++ )
    {
        RevokeRec revoke = revokeList.at(i);

        QString strCertName = manApplet->dbMgr()->getNumName( revoke.getCertNum(), "TB_CERT", "SUBJECTDN" );
        QString strIsserName = manApplet->dbMgr()->getNumName( revoke.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
        QString strReason = JS_PKI_getRevokeReasonName( revoke.getReason() );

        QTableWidgetItem *item = new QTableWidgetItem( strCertName );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( revoke.getSeq() ));
        seq->setIcon(QIcon(":/images/revoke.png"));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, item );
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( strIsserName )));
        right_table_->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(revoke.getSerial())));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg(getDateTime( revoke.getRevokeDate() ))));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( strReason )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg(revoke.getCRLDP())));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightUserList()
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_USER;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

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
        nTotalCount = manApplet->dbMgr()->getUserSearchCount( strTarget, strWord );
        manApplet->dbMgr()->getUserList( strTarget, strWord, nOffset, nLimit, userList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getUserCount();
        manApplet->dbMgr()->getUserList( nOffset, nLimit, userList );
    }

    right_table_->setColumnWidth( 0, 60 );
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

        QTableWidgetItem *item = new QTableWidgetItem( user.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( user.getNum() ));

        seq->setIcon(QIcon(":/images/user.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, item);
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( user.getSSN() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( user.getEmail() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( getUserStatusName( user.getStatus() ) )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightKMSList()
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_KMS;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Status"), tr("Type"), tr("Algorithm"), tr("ID"), tr("Info") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<KMSRec> kmsList;

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );
    right_table_->setColumnWidth( 5, 100 );

    if( strWord.length() > 0 )
    {
        nTotalCount = manApplet->dbMgr()->getKMSSearchCount( strTarget, strWord );
        manApplet->dbMgr()->getKMSList( strTarget, strWord, nOffset, nLimit, kmsList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getKMSCount();
        manApplet->dbMgr()->getKMSList( nOffset, nLimit, kmsList );
    }


    for( int i = 0; i < kmsList.size(); i++ )
    {
        char sRegTime[64];
        KMSRec kms = kmsList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );

        QString strType = JS_KMS_getObjectTypeName( kms.getType() );
        QString strAlgorithm = JS_PKI_getKeyTypeName( kms.getAlgorithm() );

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( kms.getSeq() ));
        seq->setIcon(QIcon(":/images/kms.png"));

        JS_UTIL_getDateTime( kms.getRegTime(), sRegTime );

        right_table_->setItem(i,0, seq);
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getStatusName( kms.getState() ))));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( strType )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( strAlgorithm )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( kms.getID() )));
        right_table_->setItem(i,6, new QTableWidgetItem(QString("%1").arg( kms.getInfo() )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightSignerList(int nType)
{
    search_form_->hide();
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
    manApplet->dbMgr()->getSignerList( nType, signerList );


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

        QTableWidgetItem *item = new QTableWidgetItem( signer.getDN() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( signer.getNum() ));

        if( nType == SIGNER_TYPE_REG )
            seq->setIcon(QIcon(":/images/reg_signer.png"));
        else if( nType == SIGNER_TYPE_OCSP )
            seq->setIcon(QIcon(":/images/ocsp_signer.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getSignerTypeName( signer.getType() ))));
        right_table_->setItem(i,3, item );
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( getStatusName( signer.getStatus() ))));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( signer.getDNHash() )));
    }
}

void MainWindow::createRightAdminList()
{
    search_form_->hide();
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
    manApplet->dbMgr()->getAdminList( adminList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 60 );
    right_table_->setColumnWidth( 3, 160 );
    right_table_->setColumnWidth( 4, 160 );


    for( int i = 0; i < adminList.size(); i++ )
    {
        AdminRec admin = adminList.at(i);

        QTableWidgetItem *item = new QTableWidgetItem( admin.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( admin.getSeq() ));
        seq->setIcon(QIcon(":/images/admin.png"));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( getStatusName( admin.getStatus() ) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getAdminTypeName( admin.getType() ) )));
        right_table_->setItem(i,3, item );
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( admin.getPassword() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( admin.getEmail() )));
    }
}

void MainWindow::createRightConfigList()
{
    search_form_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_CONFIG;

    QStringList headerList = { tr("Num"), tr("Kind"), tr("Name"), tr("Value") };

    right_table_->clear();
    right_table_->horizontalHeader()->setStretchLastSection(true);
    QString style = "QHeaderView::section {background-color:#404040;color:#FFFFFF;}";
    right_table_->horizontalHeader()->setStyleSheet( style );

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<ConfigRec> configList;
    manApplet->dbMgr()->getConfigList( configList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 60 );
    right_table_->setColumnWidth( 2, 60 );


    for( int i = 0; i < configList.size(); i++ )
    {
        ConfigRec config = configList.at(i);

        QTableWidgetItem *item = new QTableWidgetItem( config.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( config.getNum() ));
        seq->setIcon(QIcon(":/images/config.png"));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( config.getKind() )));
        right_table_->setItem(i,2, item);
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( config.getValue() )));
    }
}


void MainWindow::createRightAuditList()
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_AUDIT;

    int nTotalCount = 0;
//    int nLimit = kListCount;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Kind"), tr("Operation"), tr("UserName"), tr("Info") };

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
        nTotalCount = manApplet->dbMgr()->getAuditSearchCount( strTarget, strWord );
        manApplet->dbMgr()->getAuditList( strTarget, strWord, nOffset, nLimit, auditList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getAuditCount();
        manApplet->dbMgr()->getAuditList( nOffset, nLimit, auditList );
    }

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 140 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 100 );
    right_table_->setColumnWidth( 4, 100 );

    for( int i = 0; i < auditList.size(); i++ )
    {
        char sRegTime[64];
        AuditRec audit = auditList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        QString strKind = JS_GEN_getKindName( audit.getKind() );
        QString strOperation = JS_GEN_getOperationName( audit.getOperation() );

        JS_UTIL_getDateTime( audit.getRegTime(), sRegTime );

        QTableWidgetItem *item = new QTableWidgetItem( strOperation );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( audit.getSeq() ));
        seq->setIcon(QIcon(":/images/audit.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( strKind )));
        right_table_->setItem(i,3, item );
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( audit.getUserName() )));
        right_table_->setItem(i,5, new QTableWidgetItem(QString("%1").arg( audit.getInfo() )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightTSPList()
{
    search_form_->show();

    removeAllRight();
    right_type_ = RightType::TYPE_TSP;

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

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
        nTotalCount = manApplet->dbMgr()->getTSPSearchCount( strTarget, strWord );
        manApplet->dbMgr()->getTSPList( strTarget, strWord, nOffset, nLimit, tspList );
    }
    else
    {
        nTotalCount = manApplet->dbMgr()->getAuditCount();
        manApplet->dbMgr()->getTSPList( nOffset, nLimit, tspList );
    }

    right_table_->setColumnWidth( 0, 60 );
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

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( tsp.getSeq() ));
        seq->setIcon(QIcon(":/images/timestamp.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( sRegTime )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( tsp.getSerial())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( tsp.getSrcHash() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( tsp.getPolicy() )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightStatistics()
{
    printf( "Set Statistics\n" );
    //stack_->addWidget( statistics_ );
    stack_->setCurrentIndex(1);
}

void MainWindow::infoKeyPair(int seq)
{
    if( manApplet->dbMgr() == NULL ) return;
    KeyPairRec keyPair;

    manApplet->dbMgr()->getKeyPairRec( seq, keyPair );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== KeyPair Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num        : %1\n").arg( keyPair.getNum() ));
    manApplet->info( QString("Algorithm  : %1\n").arg(keyPair.getAlg()));
    manApplet->info( QString("Name       : %1\n").arg(keyPair.getName()));
    manApplet->info( QString("PublicKey  : %1\n").arg(keyPair.getPublicKey()));
    manApplet->info( QString("PrivateKey : %1\n").arg(keyPair.getPrivateKey()));
    manApplet->info( QString("Param      : %1\n").arg(keyPair.getParam()));
    manApplet->info( QString("Status     : %1 - %2\n").arg(keyPair.getStatus()).arg(getRecStatusName(keyPair.getStatus())));

    infoCursorTop();
}

void MainWindow::infoRequest( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    ReqRec reqRec;
    manApplet->dbMgr()->getReqRec( seq, reqRec );

    QString strKeyName = manApplet->dbMgr()->getNumName( reqRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Request Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("SEQ      : %1\n").arg(reqRec.getSeq()));
    manApplet->info( QString("KeyNum   : %1 - %2\n").arg(reqRec.getKeyNum()).arg( strKeyName ));
    manApplet->info( QString("Name     : %1\n").arg(reqRec.getName()));
    manApplet->info( QString("DN       : %1\n").arg(reqRec.getDN()));
    manApplet->info( QString("Request  : %1\n").arg(reqRec.getCSR()));
    manApplet->info( QString("Hash     : %1\n").arg(reqRec.getHash()));
    manApplet->info( QString("Status   : %1 - %2\n").arg(reqRec.getStatus()).arg( getRecStatusName(reqRec.getStatus())));

    infoCursorTop();
}

void MainWindow::infoCertificate( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    char    sRegDate[64];

    CertRec certRec;
    manApplet->dbMgr()->getCertRec( seq, certRec );

    QString strKeyName;
    QString strUserName;
    QString strIssuerName;

    if( certRec.getKeyNum() > 0 )
        strKeyName = manApplet->dbMgr()->getNumName( certRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );
    else
        strKeyName = "Unknown";

    if( certRec.getIssuerNum() > 0 )
        strIssuerName = manApplet->dbMgr()->getNumName( certRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
    else
        strIssuerName = "Unknown";


    if( certRec.getUserNum() > 0 )
        strUserName = manApplet->dbMgr()->getNumName( certRec.getUserNum(), "TB_USER", "NAME" );
    else
        strUserName = "Unknown";

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Certificate Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num           : %1\n").arg(certRec.getNum()));
    JS_UTIL_getDateTime( certRec.getRegTime(), sRegDate );
    manApplet->info( QString("RegDate       : %1\n").arg(sRegDate));
    manApplet->info( QString("KeyNum        : %1 - %2\n").arg(certRec.getKeyNum()).arg( strKeyName ));

    if( manApplet->isPRO() )
        manApplet->info( QString("UserNum       : %1 - %2\n").arg(certRec.getUserNum()).arg( strUserName ));

    manApplet->info( QString("SignAlgorithm : %1\n").arg(certRec.getSignAlg()));
    manApplet->info( QString("Certificate   : %1\n").arg(certRec.getCert()));
    manApplet->info( QString("IsCA          : %1\n").arg(certRec.isCA()));
    manApplet->info( QString("IsSelf        : %1\n").arg(certRec.isSelf()));
    manApplet->info( QString("SubjectDN     : %1\n").arg(certRec.getSubjectDN()));
    manApplet->info( QString("IssuerNum     : %1 - %2\n").arg(certRec.getIssuerNum()).arg( strIssuerName ));
    manApplet->info( QString("Status        : %1 - %2\n").arg(certRec.getStatus()).arg( getCertStatusName( certRec.getStatus() )));
    manApplet->info( QString("Serial        : %1\n").arg(certRec.getSerial()));
    manApplet->info( QString("DNHash        : %1\n").arg(certRec.getDNHash()));
    manApplet->info( QString("KeyHash       : %1\n").arg(certRec.getKeyHash()));
    manApplet->info( QString("CRLDP         : %1\n").arg(certRec.getCRLDP()));

    infoCursorTop();
}

void MainWindow::infoCertProfile( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    CertProfileRec certProfile;

    manApplet->dbMgr()->getCertProfileRec( seq, certProfile );

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
    else if( certProfile.getNotBefore() == 1 )
    {
        strNotBefore = "GenTime";
        strNotAfter = QString( "%1 Months" ).arg( certProfile.getNotAfter() );
    }
    else if( certProfile.getNotBefore() == 2 )
    {
        strNotBefore = "GenTime";
        strNotAfter = QString( "%1 Years" ).arg( certProfile.getNotAfter() );
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

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Certificate Profile Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num         : %1\n").arg(certProfile.getNum()));
    manApplet->info( QString("Name        : %1\n").arg(certProfile.getName()));
    manApplet->info( QString("Type        : %1 - %2\n").arg(certProfile.getType()).arg( getProfileType( certProfile.getType())));
    manApplet->info( QString("Version     : %1 - %2\n").arg(certProfile.getVersion()).arg( strVersion ));
    manApplet->info( QString("NotBefore   : %1 - %2\n").arg(certProfile.getNotBefore()).arg(strNotBefore));
    manApplet->info( QString("NotAfter    : %1 - %2\n").arg(certProfile.getNotAfter()).arg(strNotAfter));
    manApplet->info( QString("ExtUsage    : %1 - %2\n").arg(certProfile.getExtUsage()).arg(getExtUsage(certProfile.getExtUsage())));
    manApplet->info( QString("Hash        : %1\n").arg(certProfile.getHash()));
    manApplet->info( QString("DNTemplate  : %1 - %2\n").arg(certProfile.getDNTemplate()).arg(strDNTemplate));
    manApplet->info( "======================= Extension Information ==========================\n" );
    QList<ProfileExtRec> extList;
    manApplet->dbMgr()->getCertProfileExtensionList( seq, extList );

    for( int i = 0; i < extList.size(); i++ )
    {
        ProfileExtRec extRec = extList.at(i);

        manApplet->info( QString( "%1 || %2 || %3 || %4\n")
                .arg(extRec.getSeq())
                .arg(extRec.isCritical())
                .arg(extRec.getSN())
                .arg(extRec.getValue()) );
    }

    infoCursorTop();
}

void MainWindow::infoCRL( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    CRLRec crlRec;
    char    sRegTime[64];

    manApplet->dbMgr()->getCRLRec( seq, crlRec );
    QString strIssuerName;

    if( crlRec.getIssuerNum() > 0 )
        strIssuerName = manApplet->dbMgr()->getNumName( crlRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
    else
        strIssuerName = "Unknown";


    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== CRL Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num           : %1\n").arg(crlRec.getNum()));
    JS_UTIL_getDateTime( crlRec.getRegTime(), sRegTime );
    manApplet->info( QString("RegTime       : %1\n").arg(sRegTime));
    manApplet->info( QString("IssuerNum     : %1 - %2\n").arg(crlRec.getIssuerNum()).arg( strIssuerName ));
    manApplet->info( QString("SignAlgorithm : %1\n").arg(crlRec.getSignAlg()));
    manApplet->info( QString("CRLDP         : %1\n").arg(crlRec.getCRLDP()));
    manApplet->info( QString("CRL           : %1\n").arg(crlRec.getCRL()));

    infoCursorTop();
}

void MainWindow::infoCRLProfile( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    CRLProfileRec crlProfile;

    manApplet->dbMgr()->getCRLProfileRec( seq, crlProfile );

    QString strVersion;
    QString strLastUpdate;
    QString strNextUpdate;

    strVersion = QString( "V%1" ).arg( crlProfile.getVersion() + 1);

    if( crlProfile.getLastUpdate() == 0 )
    {
        strLastUpdate = "GenTime";
        strNextUpdate = QString( "%1 Days" ).arg( crlProfile.getNextUpdate() );
    }
    else if( crlProfile.getLastUpdate() == 1 )
    {
        strLastUpdate = "GenTime";
        strNextUpdate = QString( "%1 Months" ).arg( crlProfile.getNextUpdate() );
    }
    else if( crlProfile.getLastUpdate() == 2 )
    {
        strLastUpdate = "GenTime";
        strNextUpdate = QString( "%1 Years" ).arg( crlProfile.getNextUpdate() );
    }
    else
    {
        strLastUpdate = getDateTime( crlProfile.getLastUpdate() );
        strNextUpdate = getDateTime( crlProfile.getNextUpdate() );
    }

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== CRL Profile Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num          : %1\n").arg(crlProfile.getNum()));
    manApplet->info( QString("Name         : %1\n").arg(crlProfile.getName()));
    manApplet->info( QString("Version      : %1 - %2\n").arg(crlProfile.getVersion()).arg(strVersion));
    manApplet->info( QString("LastUpdate   : %1 - %2\n").arg(crlProfile.getLastUpdate()).arg(strLastUpdate));
    manApplet->info( QString("NextUpdate   : %1 - %2\n").arg(crlProfile.getNextUpdate()).arg(strNextUpdate));
    manApplet->info( QString("Hash         : %1\n").arg(crlProfile.getHash()));
    manApplet->info( "======================= Extension Information ==========================\n" );

    QList<ProfileExtRec> extList;
    manApplet->dbMgr()->getCRLProfileExtensionList( seq, extList );

    for( int i = 0; i < extList.size(); i++ )
    {
        ProfileExtRec extRec = extList.at(i);

        manApplet->info( QString( "%1 || %2 || %3 || %4\n")
                .arg(extRec.getSeq())
                .arg(extRec.isCritical())
                .arg(extRec.getSN())
                .arg(extRec.getValue()));
    }

    infoCursorTop();
}

void MainWindow::infoRevoke( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    RevokeRec revokeRec;
    manApplet->dbMgr()->getRevokeRec( seq, revokeRec );

    QString strCertName = manApplet->dbMgr()->getNumName( revokeRec.getCertNum(), "TB_CERT", "SUBJECTDN" );
    QString strIsserName = manApplet->dbMgr()->getNumName( revokeRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
    QString strReason = JS_PKI_getRevokeReasonName( revokeRec.getReason() );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Revoke Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Seq          : %1\n").arg( revokeRec.getSeq()));
    manApplet->info( QString("CertNum      : %1 - %2\n").arg( revokeRec.getCertNum()).arg(strCertName));
    manApplet->info( QString("IssuerNum    : %1 - %2\n").arg( revokeRec.getIssuerNum()).arg(strIsserName));
    manApplet->info( QString("Serial       : %1\n").arg( revokeRec.getSerial()));
    manApplet->info( QString("RevokeDate   : %1\n").arg( getDateTime( revokeRec.getRevokeDate() )));
    manApplet->info( QString("Reason       : %1 - %2\n").arg( revokeRec.getReason()).arg(strReason));
    manApplet->info( QString("CRLDP        : %1\n").arg( revokeRec.getCRLDP()));

    infoCursorTop();
}

void MainWindow::infoUser( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    UserRec userRec;
    manApplet->dbMgr()->getUserRec( seq, userRec );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== User Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num           : %1\n").arg(userRec.getNum()));
    manApplet->info( QString("RegTime       : %1\n").arg(getDateTime(userRec.getRegTime())));
    manApplet->info( QString("Name          : %1\n").arg(userRec.getName()));
    manApplet->info( QString("SSN           : %1\n").arg(userRec.getSSN()));
    manApplet->info( QString("Email         : %1\n").arg(userRec.getEmail()));
    manApplet->info( QString("Status        : %1 - %2\n").arg(userRec.getStatus()).arg(getUserStatusName(userRec.getStatus())));
    manApplet->info( QString("RefNum        : %1\n").arg(userRec.getRefNum()));
    manApplet->info( QString("AuthCode      : %1\n").arg(userRec.getAuthCode()));

    infoCursorTop();
}

void MainWindow::infoAdmin( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    AdminRec adminRec;
    manApplet->dbMgr()->getAdminRec( seq, adminRec );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Admin Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Seq          : %1\n").arg(adminRec.getSeq()));
    manApplet->info( QString("Status       : %1 - %2\n").arg(adminRec.getStatus()).arg(getStatusName(adminRec.getStatus())));
    manApplet->info( QString("Type         : %1 - %2\n").arg(adminRec.getType()).arg(getAdminTypeName(adminRec.getType())));
    manApplet->info( QString("Name         : %1\n").arg(adminRec.getName()));
    manApplet->info( QString("Password     : %1\n").arg(adminRec.getPassword()));
    manApplet->info( QString("Email        : %1\n").arg(adminRec.getEmail()));

    infoCursorTop();
}

void MainWindow::infoConfig( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    ConfigRec configRec;
    manApplet->dbMgr()->getConfigRec( seq, configRec );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Config Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num          : %1\n").arg(configRec.getNum()));
    manApplet->info( QString("Kind         : %1\n").arg(configRec.getKind()));
    manApplet->info( QString("Name         : %1\n").arg(configRec.getName()));
    manApplet->info( QString("Value        : %1\n").arg(configRec.getValue()));

    infoCursorTop();
}

void MainWindow::infoKMS( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    KMSRec kmsRec;
    manApplet->dbMgr()->getKMSRec( seq, kmsRec );

    QString strType = JS_KMS_getObjectTypeName( kmsRec.getType() );
    QString strAlgorithm = JS_PKI_getKeyTypeName( kmsRec.getAlgorithm() );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== KMS Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Seq         : %1\n").arg(kmsRec.getSeq()));
    manApplet->info( QString("RegTime     : %1\n").arg(getDateTime(kmsRec.getRegTime())));
    manApplet->info( QString("State       : %1 - %2\n").arg(kmsRec.getState()).arg( getStatusName(kmsRec.getState())));
    manApplet->info( QString("Type        : %1 - %2\n").arg(kmsRec.getType()).arg(strType));
    manApplet->info( QString("Algorithm   : %1 - %2\n").arg(kmsRec.getAlgorithm()).arg( strAlgorithm ));
    manApplet->info( QString("ID          : %1\n").arg(kmsRec.getID()));
    manApplet->info( QString("Info        : %1\n").arg(kmsRec.getInfo()));
    manApplet->info( "============================ Attribute =================================\n" );

    QList<KMSAttribRec> kmsAttribList;
    manApplet->dbMgr()->getKMSAttribList( seq, kmsAttribList );

    for( int i = 0; i < kmsAttribList.size(); i++ )
    {
        KMSAttribRec attribRec = kmsAttribList.at(i);

        manApplet->info( QString( "%1 || %2 || %3\n")
                .arg(attribRec.getNum())
                .arg(JS_KMS_attributeName(attribRec.getType()))
                .arg(attribRec.getValue()));
    }

    infoCursorTop();
}

void MainWindow::infoAudit( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    AuditRec auditRec;
    manApplet->dbMgr()->getAuditRec( seq, auditRec );

    QString strKind = JS_GEN_getKindName( auditRec.getKind() );
    QString strOperation = JS_GEN_getOperationName( auditRec.getOperation() );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Audit Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Seq          : %1\n").arg(auditRec.getSeq()));
    manApplet->info( QString("Kind         : %1 - %2\n").arg(auditRec.getKind()).arg(strKind));
    manApplet->info( QString("Operation    : %1 - %2\n").arg(auditRec.getOperation()).arg(strOperation));
    manApplet->info( QString("UserName     : %1\n").arg(auditRec.getUserName()));
    manApplet->info( QString("Info         : %1\n").arg(auditRec.getInfo()));
    manApplet->info( QString("MAC          : %1\n").arg(auditRec.getMAC()));

    infoCursorTop();
}

void MainWindow::infoTSP( int seq )
{
    if( manApplet->dbMgr() == NULL ) return;

    TSPRec tspRec;
    manApplet->dbMgr()->getTSPRec( seq, tspRec );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== TSP Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Seq          : %1\n").arg(tspRec.getSeq()));
    manApplet->info( QString("RegTime      : %1\n").arg(getDateTime(tspRec.getRegTime())));
    manApplet->info( QString("Serial       : %1\n").arg(tspRec.getSerial()));
    manApplet->info( QString("Policy       : %1\n").arg(tspRec.getPolicy()));
    manApplet->info( QString("TSTInfo      : %1\n").arg(tspRec.getTSTInfo()));
    manApplet->info( QString("Data         : %1\n").arg(tspRec.getData()));

    infoCursorTop();
}

void MainWindow::infoSigner(int seq)
{
    if( manApplet->dbMgr() == NULL ) return;

    SignerRec signerRec;
    manApplet->dbMgr()->getSignerRec( seq, signerRec );

    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Signer Information\n" );
    manApplet->info( "========================================================================\n" );
    manApplet->info( QString("Num          : %1\n").arg( signerRec.getNum()));
    manApplet->info( QString("RegTime      : %1\n").arg(getDateTime(signerRec.getRegTime())));
    manApplet->info( QString("Type         : %1 - %2\n").arg(signerRec.getType()).arg(getSignerTypeName(signerRec.getType())));
    manApplet->info( QString("DN           : %1\n").arg(signerRec.getDN()));
    manApplet->info( QString("DNHash       : %1\n").arg(signerRec.getDNHash()));
    manApplet->info( QString("Cert         : %1\n").arg(signerRec.getCert()));
    manApplet->info( QString("Status       : %1 - %2\n").arg(signerRec.getStatus()).arg(getStatusName(signerRec.getType())));
    manApplet->info( QString("Info         : %1\n").arg(signerRec.getInfo()));

    infoCursorTop();
}

void MainWindow::infoStatistics()
{
    manApplet->mainWindow()->infoClear();
    manApplet->info( "========================================================================\n" );
    manApplet->info( "== Statistics Information\n" );
    manApplet->info( "========================================================================\n" );

    infoCursorTop();
}

int MainWindow::rightCount()
{
    return right_table_->rowCount();
}

void MainWindow::loadDB( const QString& filename )
{
    openDB( filename );
}
