/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFileDialog>
#include <QtWidgets>

#include "js_util.h"
#include "js_gen.h"
#include "js_ocsp.h"
#include "js_http.h"
#include "js_cmp.h"
#include "js_json_msg.h".h"
#include "js_pkcs7.h"
#include "js_scep.h"
#include "js_pki_ext.h"
#include "js_pki_tools.h"
#include "js_define.h"
#include "js_error.h"

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
#include "get_uri_dlg.h"
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

#include "pki_srv_dlg.h"
#include "ca_man_dlg.h"
#include "profile_man_dlg.h"
#include "view_cert_profile_dlg.h"
#include "view_crl_profile_dlg.h"

const int kMaxRecentFiles = 10;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    createActions();
    createStatusBar();
    createMemberDlg();

    setUnifiedTitleAndToolBarOnMac(true);
    setAcceptDrops(true);

    right_type_ = -1;
    root_ca_ = NULL;
    log_halt_ = false;
#if defined( Q_OS_MAC )
    layout()->setSpacing(5);
#endif

    initialize();
}

MainWindow::~MainWindow()
{
    recent_file_list_.clear();

    delete root_ca_;

    delete left_tree_;
    delete left_model_;

    if( pki_srv_ ) delete pki_srv_;

    delete log_text_;
    delete info_text_;

    delete search_form_;

#ifdef _ENABLE_CHARTS
    delete stat_;
    delete stack_;
#endif

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
        manApplet->warningBox( tr("Database is already open"), this );
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

void MainWindow::closeEvent(QCloseEvent *event)
{
//    exit(0);
    manApplet->exitApp(0);
}

void MainWindow::setTitle(const QString strName)
{
    QString strTitle = manApplet->getBrand();

    if( manApplet->isLicense() == false )
        strTitle += " (Unlicensed version)";

    if( strName.length() >= 1 )
        strTitle += QString( " - %1" ).arg( strName );

    setWindowTitle( strTitle );
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

    log_text_ = new QPlainTextEdit();
    log_text_->setReadOnly(true);

    info_text_ = new CodeEditor();
    info_text_->setReadOnly(true);

    right_table_->setSelectionBehavior(QAbstractItemView::SelectRows); // 한라인 전체 선택
    right_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);  // Edit 불가
    right_table_->setSelectionMode(QAbstractItemView::SingleSelection); // 하나만 선택 가능
//    right_table_->setAlternatingRowColors(true);
//    right_table_->setAttribute(Qt::WA_MacShowFocusRect, 0);
//    right_table_->setSortingEnabled(false);
    right_table_->horizontalHeader()->setStretchLastSection(true);
    right_table_->horizontalHeader()->setStyleSheet( kTableStyle );
    right_table_->horizontalHeader()->setHighlightSections(false);

    QWidget *rightWidget = new QWidget;


    hsplitter_->addWidget(left_tree_);

#ifdef _ENABLE_CHARTS
    stack_ = new QStackedLayout();
    stat_ = new StatForm;

    stack_->addWidget( vsplitter_ );
    stack_->addWidget( stat_ );
    rightWidget->setLayout(stack_);
    hsplitter_->addWidget( rightWidget );
#else
    hsplitter_->addWidget( vsplitter_ );
#endif


    vsplitter_->addWidget(right_table_);
    vsplitter_->addWidget( search_form_ );

    text_tab_ = new QTabWidget;
    vsplitter_->addWidget(text_tab_);
    text_tab_->setTabPosition( QTabWidget::South );
    text_tab_->addTab( info_text_, tr( "Information" ));
    text_tab_->addTab( log_text_, tr( "Log" ));

    if( manApplet->isLicense() == false )
    {
        text_tab_->setTabEnabled( 1, false );
    }

#ifdef Q_OS_MACOS
    int nWidth = 980;
    resize( nWidth, 740 );

    QList<int> sizes;
    sizes.append( 300 );
    sizes.append( nWidth - 300);
    hsplitter_->setSizes( sizes );
#else
    resize( 940, 740 );
#endif

    setCentralWidget(hsplitter_);


    connect( left_tree_, SIGNAL(clicked(QModelIndex)), this, SLOT(treeMenuClick(QModelIndex)));
    connect( left_tree_, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(treeMenuDoubleClick(QModelIndex)));
    connect( right_table_, SIGNAL(clicked(QModelIndex)), this, SLOT(tableClick(QModelIndex)));
    connect( right_table_, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(doubleClickRightTable(QModelIndex)));

    right_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect( right_table_, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showRightMenu(QPoint)));

    setTitle("");
}


void MainWindow::createActions()
{
    int nWidth = 24;
    int nHeight = 24;
    int nSpacing = 0;

    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    file_tool_ = addToolBar(tr("File"));

    file_tool_->setIconSize( QSize(nWidth, nHeight));
    file_tool_->layout()->setSpacing(nSpacing);

    const QIcon newIcon = QIcon::fromTheme("document-new", QIcon(":/images/new.png"));
    new_act_ = new QAction( newIcon, tr("&New"), this);
    new_act_->setShortcut( QKeySequence::New);
    new_act_->setStatusTip(tr("Create a new database"));
    connect( new_act_, &QAction::triggered, this, &MainWindow::newFile);
    fileMenu->addAction(new_act_);
    if( isView( ACT_FILE_NEW ) ) file_tool_->addAction(new_act_);

    const QIcon openIcon = QIcon::fromTheme("document-open", QIcon(":/images/open.png"));
    open_act_ = new QAction( openIcon, tr("&Open..."), this );
    open_act_->setShortcut(QKeySequence::Open);
    open_act_->setStatusTip(tr("Open a database"));
    connect( open_act_, &QAction::triggered, this, &MainWindow::open);
    fileMenu->addAction(open_act_);
    if( isView( ACT_FILE_OPEN ) ) file_tool_->addAction(open_act_);

    const QIcon remotedbIcon = QIcon::fromTheme("remotedb", QIcon(":/images/remotedb.png"));
    remote_db_act_ = new QAction( remotedbIcon, tr("&Remote Database"), this );
    remote_db_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_R));
    remote_db_act_->setStatusTip(tr("Connect remote database"));
    connect( remote_db_act_, &QAction::triggered, this, &MainWindow::remoteDB);
    fileMenu->addAction(remote_db_act_);
    if( isView( ACT_FILE_REMOTE_DB ) ) file_tool_->addAction(remote_db_act_);

    const QIcon logoutIcon = QIcon::fromTheme("logout", QIcon(":/images/logout.png"));
    logout_act_ = new QAction( logoutIcon, tr("&Logout"), this );
    logout_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_T));
    logout_act_->setStatusTip(tr("Logout current database"));
    connect( logout_act_, &QAction::triggered, this, &MainWindow::logout);
    fileMenu->addAction(logout_act_);
    if( isView( ACT_FILE_LOGOUT ) ) file_tool_->addAction(logout_act_);

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

    quit_act_ = new QAction(tr("&Quit"), this );
    quit_act_->setShortcut(QKeySequence::Quit);
    quit_act_->setStatusTip( tr("Quit CertMan") );
    connect( quit_act_, &QAction::triggered, this, &MainWindow::quit);
    fileMenu->addAction( quit_act_ );

    if( manApplet->isLicense() ) createViewActions();

    QMenu *toolsMenu = menuBar()->addMenu(tr("&Tools"));
    tool_tool_ = addToolBar(tr("Tools"));

    tool_tool_->setIconSize( QSize(nWidth, nHeight));
    tool_tool_->layout()->setSpacing(nSpacing);

    const QIcon newKeyIcon = QIcon::fromTheme("new-key", QIcon(":/images/key_reg.png"));
    new_key_act_ = new QAction( newKeyIcon, tr("&New keypair"), this );
    new_key_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F1 ));
    new_key_act_->setStatusTip(tr("Generate new keypair"));
    connect( new_key_act_, &QAction::triggered, this, &MainWindow::newKey );
    toolsMenu->addAction( new_key_act_ );
    if( isView( ACT_TOOL_NEW_KEY ) ) tool_tool_->addAction( new_key_act_ );

    const QIcon csrIcon = QIcon::fromTheme("certificate-request", QIcon(":/images/csr.png"));
    make_req_act_ = new QAction( csrIcon, tr("Make &Request"), this );
    make_req_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F2 ));
    make_req_act_->setStatusTip(tr( "Create a request"));
    connect( make_req_act_, &QAction::triggered, this, &MainWindow::makeRequest );
    toolsMenu->addAction( make_req_act_ );
    if( isView( ACT_TOOL_MAKE_REQ ) ) tool_tool_->addAction( make_req_act_ );

    if( manApplet->isPRO() )
    {
        const QIcon configIcon = QIcon::fromTheme( "make config", QIcon(":/images/config.png"));
        make_config_act_ = new QAction( configIcon, tr( "Make Config"), this );
        make_config_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F3 ));
        make_config_act_->setStatusTip(tr( "Generate configuration information" ));
        connect( make_config_act_, &QAction::triggered, this, &MainWindow::makeConfig );
        toolsMenu->addAction( make_config_act_ );
        if( isView( ACT_TOOL_MAKE_CONFIG ) ) tool_tool_->addAction( make_config_act_ );


        const QIcon userRegIcon = QIcon::fromTheme("user-register", QIcon(":/images/user_reg.png"));
        reg_user_act_ = new QAction( userRegIcon, tr("Register &User"), this );
        reg_user_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F4 ));
        reg_user_act_->setStatusTip(tr( "Register a user"));
        connect( reg_user_act_, &QAction::triggered, this, &MainWindow::registerUser );
        toolsMenu->addAction( reg_user_act_ );
        if( isView( ACT_TOOL_REG_USER ) ) tool_tool_->addAction( reg_user_act_ );

        const QIcon signerRegIcon = QIcon::fromTheme("signer-register", QIcon(":/images/signer_reg.png"));
        reg_signer_act_ = new QAction( signerRegIcon, tr("Register &Signer"), this );
        reg_signer_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F5 ));
        reg_signer_act_->setStatusTip(tr( "Register a signer"));
        connect( reg_signer_act_, &QAction::triggered, this, &MainWindow::registerREGSigner );
        toolsMenu->addAction( reg_signer_act_ );
        if( isView( ACT_TOOL_REG_SIGNER ) ) tool_tool_->addAction( reg_signer_act_ );
    }

    const QIcon certProfileIcon = QIcon::fromTheme("cert-profile", QIcon(":/images/cert_profile.png"));
    make_cert_profile_act_ = new QAction( certProfileIcon, tr("Make Cert &Profile"), this );
    make_cert_profile_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F6 ));
    make_cert_profile_act_->setStatusTip(tr( "Create a certificate profile"));
    connect( make_cert_profile_act_, &QAction::triggered, this, &MainWindow::makeCertProfile );
    toolsMenu->addAction( make_cert_profile_act_ );
    if( isView( ACT_TOOL_MAKE_CERT_PROFILE ) ) tool_tool_->addAction( make_cert_profile_act_ );

    const QIcon crlProfileIcon = QIcon::fromTheme("crl-profile", QIcon(":/images/crl_profile.png"));
    make_crl_profile_act_ = new QAction( crlProfileIcon, tr("Make C&RL Profile"), this );
    make_crl_profile_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F7 ));
    make_crl_profile_act_->setStatusTip(tr("Create a CRL profille"));
    connect( make_crl_profile_act_, &QAction::triggered, this, &MainWindow::makeCRLProfile);
    toolsMenu->addAction( make_crl_profile_act_ );
    if( isView( ACT_TOOL_MAKE_CRL_PROFILE ) ) tool_tool_->addAction( make_crl_profile_act_ );

    const QIcon certIcon = QIcon::fromTheme("make-certificate", QIcon(":/images/cert.png"));
    make_cert_act_ = new QAction( certIcon, tr("Make &Certificate"), this );
    make_cert_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F8 ));
    make_cert_act_->setStatusTip( tr("Create a certificate" ));
    connect( make_cert_act_, &QAction::triggered, this, &MainWindow::makeCertificate );
    toolsMenu->addAction( make_cert_act_ );
    if( isView( ACT_TOOL_MAKE_CERT ) ) tool_tool_->addAction( make_cert_act_ );


    const QIcon crlIcon = QIcon::fromTheme("make-crl", QIcon(":/images/crl.png"));
    make_crl_act_ = new QAction( crlIcon, tr("Make CR&L"), this );
    make_crl_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F9 ));
    make_crl_act_->setStatusTip( tr("Create a CRL" ));
    connect( make_crl_act_, &QAction::triggered, this, &MainWindow::makeCRL );
    toolsMenu->addAction( make_crl_act_ );
    if( isView( ACT_TOOL_MAKE_CRL ) ) tool_tool_->addAction( make_crl_act_ );

    const QIcon revokeIcon = QIcon::fromTheme("revoke-certificate", QIcon(":/images/revoke.png"));
    revoke_cert_act_ = new QAction( revokeIcon, tr("Revo&ke Certificate"), this );
    revoke_cert_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F10 ));
    revoke_cert_act_->setStatusTip( tr("Revoke a certificate" ));
    connect( revoke_cert_act_, &QAction::triggered, this, &MainWindow::revokeCertificate );
    toolsMenu->addAction( revoke_cert_act_ );
    if( isView( ACT_TOOL_REVOKE_CERT ) ) tool_tool_->addAction( revoke_cert_act_ );

    const QIcon caIcon = QIcon::fromTheme("CA Manager", QIcon(":/images/ca.png"));
    ca_man_act_ = new QAction( caIcon, tr("CA Manager"), this );
    ca_man_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F11 ));
    ca_man_act_->setStatusTip( tr("CA Manager" ));
    connect( ca_man_act_, &QAction::triggered, this, &MainWindow::CAMan );
    toolsMenu->addAction( ca_man_act_ );
    if( isView( ACT_TOOL_CA_MAN ) ) tool_tool_->addAction( ca_man_act_ );

    const QIcon profileIcon = QIcon::fromTheme("Profile Manager", QIcon(":/images/profile.png"));
    profile_man_act_ = new QAction( profileIcon, tr("Profile Manager"), this );
    profile_man_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F11 ));
    profile_man_act_->setStatusTip( tr("Profile Manager" ));
    connect( profile_man_act_, &QAction::triggered, this, &MainWindow::profileMan );
    toolsMenu->addAction( profile_man_act_ );
    if( isView( ACT_TOOL_PROFILE_MAN ) ) tool_tool_->addAction( profile_man_act_ );

    QMenu *dataMenu = menuBar()->addMenu(tr("&Data"));
    data_tool_ = addToolBar(tr("Data"));

    data_tool_->setIconSize( QSize(nWidth, nHeight));
    data_tool_->layout()->setSpacing(nSpacing);

    const QIcon diskIcon = QIcon::fromTheme("disk", QIcon(":/images/disk.png"));
    import_data_act_ = new QAction( diskIcon, tr("&Import data"), this );
    import_data_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_I ));
    import_data_act_->setStatusTip( tr( "Import data" ));
    connect( import_data_act_, &QAction::triggered, this, &MainWindow::importData );
    dataMenu->addAction( import_data_act_ );
    if( isView( ACT_DATA_IMPORT_DATA ) ) data_tool_->addAction( import_data_act_ );

    const QIcon getURIIcon = QIcon::fromTheme("Get-LDAP", QIcon(":/images/get_ldap.png"));
    get_uri_act_ = new QAction( getURIIcon, tr("&Get data from URI"), this);
    get_uri_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_U ));
    get_uri_act_->setStatusTip( tr( "Get data from URI" ));
    connect( get_uri_act_, &QAction::triggered, this, &MainWindow::getURI);
    dataMenu->addAction( get_uri_act_ );
    if( isView( ACT_DATA_GET_URI ) ) data_tool_->addAction( get_uri_act_ );

    const QIcon pubLDAPIcon = QIcon::fromTheme("Publish-LDAP", QIcon(":/images/pub_ldap.png"));
    publish_ldap_act_ = new QAction( pubLDAPIcon, tr("&Publish to LDAP"), this);
    publish_ldap_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_L ));
    connect( publish_ldap_act_, &QAction::triggered, this, &MainWindow::publishLDAP);
    publish_ldap_act_->setStatusTip(tr("Publish to LDAP"));
    dataMenu->addAction( publish_ldap_act_ );
    if( isView( ACT_DATA_PUBLISH_LDAP ) ) data_tool_->addAction( publish_ldap_act_ );

    const QIcon setPassIcon = QIcon::fromTheme("SetPasswd", QIcon(":/images/setpass.png"));
    set_passwd_act_ = new QAction( setPassIcon, tr("&Set Passwd"), this);
    set_passwd_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_P ));
    connect( set_passwd_act_, &QAction::triggered, this, &MainWindow::setPasswd);
    set_passwd_act_->setStatusTip(tr("Set private key password"));
    dataMenu->addAction( set_passwd_act_ );
    if( isView( ACT_DATA_SET_PASSWD ) ) data_tool_->addAction( set_passwd_act_ );

    const QIcon passChangeIcon = QIcon::fromTheme("ChangePasswd", QIcon(":/images/pass_change.png"));
    change_passwd_act_ = new QAction( passChangeIcon, tr("&Change Passwd"), this);
    change_passwd_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_C ));
    connect( change_passwd_act_, &QAction::triggered, this, &MainWindow::changePasswd);
    change_passwd_act_->setStatusTip(tr("Change private key password"));
    dataMenu->addAction( change_passwd_act_ );
    if( isView( ACT_DATA_CHANGE_PASSWD ) ) data_tool_->addAction( change_passwd_act_ );

    if( manApplet->isLicense() == false )
    {
        publish_ldap_act_->setEnabled( false );
        set_passwd_act_->setEnabled( false );
        change_passwd_act_->setEnabled( false );
    }


    if( manApplet->isPRO() )
    {
        const QIcon timeIcon = QIcon::fromTheme("Timestamp", QIcon(":/images/timestamp.png"));
        tsp_client_act_ = new QAction( timeIcon, tr("&TSP Client"), this);
        tsp_client_act_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_T ));
        connect( tsp_client_act_, &QAction::triggered, this, &MainWindow::tsp);
        tsp_client_act_->setStatusTip(tr("TimeStampProtocol client tool"));
        dataMenu->addAction( tsp_client_act_ );
        if( isView( ACT_DATA_TSP_CLIENT ) ) data_tool_->addAction( tsp_client_act_ );

        QMenu *serverMenu = menuBar()->addMenu(tr("&Server"));
        server_tool_ = addToolBar(tr("Server"));

        server_tool_->setIconSize( QSize(nWidth, nHeight));
        server_tool_->layout()->setSpacing(nSpacing);

        const QIcon ocspIcon = QIcon::fromTheme("OCSP", QIcon(":/images/ocsp_srv.png"));
        ocsp_act_ = new QAction( ocspIcon, tr("&OCSP Server"), this);
        ocsp_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_O));
        connect( ocsp_act_, &QAction::triggered, this, &MainWindow::OCSPSrv);
        ocsp_act_->setStatusTip(tr("Setting up an OCSP server"));
        serverMenu->addAction( ocsp_act_ );
        if( isView( ACT_SERVER_OCSP ) ) server_tool_->addAction( ocsp_act_ );

        const QIcon tspIcon = QIcon::fromTheme("TSP", QIcon(":/images/tsp_srv.png"));
        tsp_act_ = new QAction( tspIcon, tr("&TSP Server"), this);
        tsp_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_T));
        connect( tsp_act_, &QAction::triggered, this, &MainWindow::TSPSrv);
        tsp_act_->setStatusTip(tr("Setting up an TSP server"));
        serverMenu->addAction( tsp_act_ );
        if( isView( ACT_SERVER_TSP ) ) server_tool_->addAction( tsp_act_ );

        const QIcon cmpIcon = QIcon::fromTheme("CMP", QIcon(":/images/cmp_srv.png"));
        cmp_act_ = new QAction( cmpIcon, tr("&CMP Server"), this);
        cmp_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_C));
        connect( cmp_act_, &QAction::triggered, this, &MainWindow::CMPSrv);
        cmp_act_->setStatusTip(tr("Setting up an CMP server"));
        serverMenu->addAction( cmp_act_ );
        if( isView( ACT_SERVER_CMP ) ) server_tool_->addAction( cmp_act_ );

        const QIcon regIcon = QIcon::fromTheme("REG", QIcon(":/images/reg_srv.png"));
        reg_act_ = new QAction( regIcon, tr("&REG Server"), this);
        reg_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_R));
        connect( reg_act_, &QAction::triggered, this, &MainWindow::RegSrv);
        reg_act_->setStatusTip(tr("Setting up an register server"));
        serverMenu->addAction( reg_act_ );
        if( isView( ACT_SERVER_REG ) ) server_tool_->addAction( reg_act_ );

        const QIcon ccIcon = QIcon::fromTheme("CC", QIcon(":/images/cc_srv.png"));
        cc_act_ = new QAction( ccIcon, tr("&CC Server"), this);
        cc_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_A));
        connect( cc_act_, &QAction::triggered, this, &MainWindow::CCSrv);
        cc_act_->setStatusTip(tr("Setting up an CC server"));
        serverMenu->addAction( cc_act_ );
        if( isView( ACT_SERVER_CC ) ) server_tool_->addAction( cc_act_ );

        const QIcon kmsIcon = QIcon::fromTheme("KMS", QIcon(":/images/kms_srv.png"));
        kms_act_ = new QAction( kmsIcon, tr("&KMS Server"), this);
        kms_act_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_K));
        connect( kms_act_, &QAction::triggered, this, &MainWindow::KMSSrv);
        kms_act_->setStatusTip(tr("Setting up an KMS server"));
        serverMenu->addAction( kms_act_ );
        if( isView( ACT_SERVER_KMS ) ) server_tool_->addAction( kms_act_ );
    }


    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    help_tool_ = addToolBar(tr("Help"));

    help_tool_->setIconSize( QSize(nWidth, nHeight));
    help_tool_->layout()->setSpacing(nSpacing);

    if( manApplet->isPRO() )
    {
        const QIcon statusIcon = QIcon::fromTheme("server-status", QIcon(":/images/server_status.png"));
        server_status_act_ = new QAction( statusIcon, tr("Server S&tatus"), this);
        connect( server_status_act_, &QAction::triggered, this, &MainWindow::serverStatus);
        server_status_act_->setStatusTip(tr("Server Status Information"));
        helpMenu->addAction( server_status_act_ );
        if( isView( ACT_HELP_SERVER_STATUS ) ) help_tool_->addAction( server_status_act_ );
    }


    const QIcon settingIcon = QIcon::fromTheme("setting", QIcon(":/images/setting.png"));
    setting_act_ = new QAction( settingIcon, tr("&Settings"), this);
    connect( setting_act_, &QAction::triggered, this, &MainWindow::settings);
    setting_act_->setStatusTip(tr("Settings"));
    helpMenu->addAction( setting_act_ );
    if( isView( ACT_HELP_SETTING ) ) help_tool_->addAction( setting_act_ );

    const QIcon clearIcon = QIcon::fromTheme( "clear-log", QIcon(":/images/clear.png"));
    clear_log_act_ = new QAction( clearIcon, tr("&Clear Log"), this );
    connect( clear_log_act_, &QAction::triggered, this, &MainWindow::clearLog );
    clear_log_act_->setShortcut( QKeySequence(Qt::Key_F9));
    clear_log_act_->setStatusTip(tr("Clear log"));
    helpMenu->addAction( clear_log_act_ );
    if( isView( ACT_HELP_CLEAR_LOG ) ) help_tool_->addAction( clear_log_act_ );

    QIcon logIcon = QIcon::fromTheme( "log-halt", QIcon(":/images/log_halt.png" ));
    halt_log_act_ = new QAction( logIcon, tr( "&Log Halt" ), this );
    connect( halt_log_act_, &QAction::triggered, this, &MainWindow::toggleLog );
    halt_log_act_->setCheckable(true);
    halt_log_act_->setShortcut( QKeySequence(Qt::Key_F10));
    halt_log_act_->setStatusTip( tr( "Halt log" ));
    helpMenu->addAction( halt_log_act_ );
    if( isView( ACT_HELP_HALT_LOG ) ) help_tool_->addAction( halt_log_act_ );

    if( manApplet->isLicense() == false )
    {
        clear_log_act_->setEnabled( false );
        halt_log_act_->setEnabled( false );
    }

    const QIcon lcnIcon = QIcon::fromTheme("berview-license", QIcon(":/images/license.png"));
    lcn_info_act_ = new QAction( lcnIcon, tr("License Information"), this);
    connect( lcn_info_act_, &QAction::triggered, this, &MainWindow::licenseInfo);
    helpMenu->addAction( lcn_info_act_ );
    lcn_info_act_->setStatusTip(tr("License Information"));

    const QIcon certManIcon = QIcon::fromTheme("certman", QIcon(":/images/certman.png"));

    bug_issue_act_ = new QAction( certManIcon, tr("Bug or Issue Report"), this);
    connect( bug_issue_act_, &QAction::triggered, this, &MainWindow::bugIssueReport);
    helpMenu->addAction( bug_issue_act_ );
    bug_issue_act_->setStatusTip(tr("Bug or Issue Report"));

    qna_act_ = new QAction( certManIcon, tr("Q and A"), this);
    connect( qna_act_, &QAction::triggered, this, &MainWindow::qnaDiscussion);
    helpMenu->addAction( qna_act_ );
    qna_act_->setStatusTip(tr("Question and Answer"));

    about_act_ = new QAction( certManIcon, tr("&About CertMan"), this);
    connect( about_act_, &QAction::triggered, this, &MainWindow::about);
    helpMenu->addAction( about_act_ );
    help_tool_->addAction( about_act_ );
    about_act_->setShortcut( QKeySequence(Qt::Key_F1));
    about_act_->setStatusTip(tr("About CertMan"));
    if( isView( ACT_HELP_ABOUT ) ) help_tool_->addAction( about_act_ );
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createTableMenu()
{

}

void MainWindow::createMemberDlg()
{
    if( manApplet->isPRO() == true )
        pki_srv_ = new PKISrvDlg;
    else
        pki_srv_ = NULL;

    ca_man_dlg_ = new CAManDlg;
    ca_man_dlg_->setMode( CAManModeManage );
    profile_man_dlg_ = new ProfileManDlg;
    profile_man_dlg_->setMode( ProfileManModeManage );
}

void MainWindow::refreshRootCA()
{
    int rows = root_ca_->rowCount();
    root_ca_->removeRows( 0, rows );
    expandItem( root_ca_ );
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
            menu.addAction( tr( "Export"), this, &MainWindow::exportPriKeyAndCert );


            QAction* pPubCertAct = menu.addAction( tr( "Publish Certificate" ), this, &MainWindow::publishLDAP );

            if( manApplet->isLicense() == false )
            {
                pPubCertAct->setEnabled(false);
            }

            menu.addAction( tr("Status Certificate"), this, &MainWindow::certStatus );

            if( treeItem->getType() != CM_ITEM_TYPE_ROOTCA )
            {
                menu.addAction( tr("Revoke Certificate"), this, &MainWindow::revokeCertificate );

                QAction *pRenewAct = menu.addAction( tr( "Renew Certificate"), this, &MainWindow::renewCert );
                if( manApplet->isLicense() == false )
                {
                    pRenewAct->setEnabled(false);
                }
            }
        }
        else {
            menu.addAction( tr("Export Certificate"), this, &MainWindow::exportCertificate );
        }

        menu.addAction( tr( "View Certificate"), this, &MainWindow::viewCertificate );
        menu.addAction( tr("Delete Certificate" ), this, &MainWindow::deleteCertificate );

        if( manApplet->isPRO() )
        {
#ifdef USE_OCSP
            menu.addAction( tr("Check OCSP"), this, &MainWindow::checkOCSP );
#endif

#ifdef USE_CMP
            menu.addAction( tr("UpdateWithCMP"), this, &MainWindow::updateCMP );
            menu.addAction( tr("RevokeWithCMP"), this, &MainWindow::revokeCMP );
#endif
            menu.addAction( tr("StatusWithReg"), this, &MainWindow::statusByReg );
            menu.addAction( tr("RevokeWithReg"), this, &MainWindow::revokeByReg );
#ifdef USE_SCEP
            menu.addAction( tr( "RenewWithSCEP" ), this, &MainWindow::renewSCEP );
            menu.addAction( tr( "getCRLWitSCEP"), this, &MainWindow::getCRLSCEP );
#endif
        }
    }
    else if( right_type_ == RightType::TYPE_CRL )
    {
        if( treeItem->getType() != CM_ITEM_TYPE_IMPORT_CRL )
        {
            menu.addAction( tr( "Verify CRL" ), this, &MainWindow::verifyCRL );

//            if( manApplet->isLicense() == true )
            QAction* pPubCRLAct = menu.addAction( tr("Publish CRL"), this, &MainWindow::publishLDAP );
            if( manApplet->isLicense() == false )
            {
                pPubCRLAct->setEnabled(false);
            }
        }

        menu.addAction( tr("Export CRL"), this, &MainWindow::exportCRL );
        menu.addAction( tr("View CRL"), this, &MainWindow::viewCRL );
        menu.addAction( tr("Delete CRL"), this, &MainWindow::deleteCRL );
    }
    else if( right_type_ == RightType::TYPE_KEYPAIR )
    {
        menu.addAction(tr("Export PublicKey"), this, &MainWindow::exportPubKey );
        menu.addAction(tr("Export PrivateKey"), this, &MainWindow::exportPriKey );
        menu.addAction(tr("Delete KeyPair"), this, &MainWindow::deleteKeyPair);
        menu.addAction(tr("View PrivateKey"), this, &MainWindow::viewPriKey );
        menu.addAction(tr("New Key"), this, &MainWindow::newKey );

        int nStatus = item->data(Qt::UserRole).toInt();

        if( nStatus == JS_REC_STATUS_NOT_USED )
            menu.addAction(tr("Make Request"), this, &MainWindow::makeRequestSetKeyName );
    }
    else if( right_type_ == RightType::TYPE_REQUEST )
    {
        menu.addAction(tr("Export Request"), this, &MainWindow::exportRequest );
        menu.addAction(tr("Delete Request"), this, &MainWindow::deleteRequest );
        menu.addAction(tr("Import CSR"), this, &MainWindow::importCSR );
        menu.addAction(tr("View CSR"), this, &MainWindow::viewCSR );
        menu.addAction(tr("Make Request"), this, &MainWindow::makeRequest );

        int nStatus = item->data(Qt::UserRole).toInt();
        if( nStatus == JS_REC_STATUS_NOT_USED )
            menu.addAction(tr("Make Certificate"), this, &MainWindow::makeCertificate );

        if( manApplet->isPRO() )
        {
#ifdef USE_SCEP
            menu.addAction(tr("Issue with SCEP"), this, &MainWindow::issueSCEP );
#endif
        }
    }
    else if( right_type_ == RightType::TYPE_CERT_PROFILE )
    {
        menu.addAction( tr( "View CertProfile" ), this, &MainWindow::viewCertProfile );
        menu.addAction(tr("Delete CertProfile"), this, &MainWindow::deleteCertProfile );
        menu.addAction(tr("Edit CertProfile" ), this, &MainWindow::editCertProfile );
        menu.addAction(tr("Copy CertProfile"), this, &MainWindow::copyCertProfile );
    }
    else if( right_type_ == RightType::TYPE_CRL_PROFILE )
    {
        menu.addAction( tr( "View CRLProfile"), this, &MainWindow::viewCRLProfile );
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
        menu.addAction( tr( "Register User"), this, &MainWindow::registerUser );

        if( manApplet->isPRO() )
        {
#ifdef USE_CMP
            menu.addAction(tr("Issue whit CMP"), this, &MainWindow::issueCMP );
#endif
        }
    }
    else if( right_type_ == RightType::TYPE_SIGNER )
    {
        menu.addAction(tr("Delete Signer"), this, &MainWindow::deleteSigner );
    }
    else if( right_type_ == RightType::TYPE_REVOKE )
    {
        menu.addAction( tr("View Certificate"), this, &MainWindow::viewRevokeCert );
        menu.addAction( tr("Remove Certificate"), this, &MainWindow::removeRevokeCert );
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

void MainWindow::doubleClickRightTable(QModelIndex index)
{
    if( right_type_ == RightType::TYPE_KEYPAIR )
        viewPriKey();
    else if( right_type_ == RightType::TYPE_REQUEST )
        viewCSR();
    else if( right_type_ == RightType::TYPE_CERTIFICATE )
        viewCertificate();
    else if( right_type_ == RightType::TYPE_CRL )
        viewCRL();
    else if( right_type_ == RightType::TYPE_CERT_PROFILE )
        viewCertProfile();
    else if( right_type_ == RightType::TYPE_CRL_PROFILE )
        viewCRLProfile();
    else if( right_type_ == RightType::TYPE_REVOKE )
        viewRevokeCert();
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

        left_tree_->expand( pManItem->index() );

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

        left_tree_->expand( pServiceItem->index() );

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
        manApplet->warningBox( tr("Database is already open"), this );
        return;
    }

    SetPassDlg setPassDlg;
    if( setPassDlg.exec() != QDialog::Accepted )
        return;

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
        manApplet->warningBox( tr( "failed to open database: %1").arg(ret), this );
        return;
    }
    else
    {
        manApplet->messageBox( tr( "The data(%1) is created successfully" ).arg(fileName), this );
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
        manApplet->warningBox( tr( "failed to open database"), this );
        return ret;
    }

    QString strConf;

    manApplet->dbMgr()->getConfigValue( JS_GEN_KIND_CERTMAN, "Passwd", strConf );

    if( strConf.length() > 1 )
    {
        LoginDlg loginDlg;
        if( loginDlg.exec() != QDialog::Accepted )
        {
            manApplet->dbMgr()->close();
            manApplet->clearPasswdKey();
            return -1;
        }
    }

    createTreeMenu();

    if( manApplet->isPRO() == true )
    {
        if( manApplet->trayIcon()->supportsMessages() )
            manApplet->trayIcon()->showMessage( "CertMan", tr("The CertMan is open"), QSystemTrayIcon::Information, 10000 );
    }

    if( ret == 0 )
    {
        setTitle( dbPath );
        adjustForCurrentFile( dbPath );
        if( manApplet->isPRO() ) addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_OPENDB, "" );
        manApplet->setDBPath( dbPath );
    }

    return ret;
}

int MainWindow::saveKeyPair( const QString strName, const BIN *pPubInfo, const BIN *pPri )
{
    int ret = 0;
    int seq = -1;
    int nType = -1;
    int nOption = -1;
    QString strAlg;
    QString strParam;
    QString strPriHex;

    KeyPairRec  keyPair;
    seq = manApplet->dbMgr()->getNextVal( "TB_KEY_PAIR" );

    ret = JS_PKI_getPubKeyInfo( pPubInfo, &nType, &nOption );
    if( ret != 0 ) return -1;

    if( nType == JS_PKI_KEY_TYPE_RSA )
    {
        strAlg = JS_PKI_KEY_NAME_RSA;
        strParam = QString( "%1" ).arg( nOption );
    }
    else if( nType == JS_PKI_KEY_TYPE_ECDSA || nType == JS_PKI_KEY_TYPE_SM2 )
    {
        strAlg = JS_PKI_KEY_NAME_ECDSA;
        strParam = JS_PKI_getSNFromNid( nOption );
    }
    else if( nType == JS_PKI_KEY_TYPE_DSA )
    {
        strAlg = JS_PKI_KEY_NAME_DSA;
        strParam = QString( "%1" ).arg( nOption );
    }
    else if( nType == JS_PKI_KEY_TYPE_EDDSA )
    {
        strAlg = JS_PKI_KEY_NAME_EDDSA;
        strParam = JS_EDDSA_getParamName( nOption );
    }
    else if( nType == JS_PKI_KEY_TYPE_ML_DSA )
    {
        strAlg = JS_PKI_KEY_NAME_ML_DSA;
        strParam = JS_PQC_paramName( nOption );
    }
    else if( nType == JS_PKI_KEY_TYPE_SLH_DSA )
    {
        strAlg = JS_PKI_KEY_NAME_SLH_DSA;
        strParam = JS_PQC_paramName( nOption );
    }
    else {
        return -1;
    }

    if( manApplet->isPasswd() )
        strPriHex = manApplet->getEncPriHex( pPri );
    else
        strPriHex = getHexString( pPri );

    keyPair.setNum( seq );
    keyPair.setAlg( strAlg );
    keyPair.setParam( strParam );
    keyPair.setName( strName );
    keyPair.setRegTime( time(NULL) );
    keyPair.setStatus( 0 );

    keyPair.setPublicKey( getHexString( pPubInfo ) );
    keyPair.setPrivateKey( strPriHex );

    manApplet->dbMgr()->addKeyPairRec( keyPair );

    return seq;
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
        QString strippedName = QString( "%1 ").arg(i+1);
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
        manApplet->warningBox( tr("Database is already open"), this );
        return;
    }

    QString strPath = manApplet->getDBPath();
    QString fileName = manApplet->findFile( this, JS_FILE_TYPE_DB, strPath, false );
    if( fileName.length() < 1 ) return;

    int ret = openDB( fileName );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "failed to open database[%1]" ).arg( JSR_DB_OPEN_FAIL ), this );
        return;
    }
}

void MainWindow::remoteDB()
{
    if( manApplet->dbMgr()->isOpen() )
    {
        manApplet->warningBox( tr("Database is already open"), this );
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
        manApplet->warningBox( tr( "Database is not connected"), this );
    }
    else
    {
        bool bVal = manApplet->yesOrNoBox( tr( "Are you sure to close database?"), this, false );
        if( bVal == false ) return;

        dbMgr->close();
        removeAllRight();
        left_model_->clear();
        manApplet->clearPasswdKey();
        manApplet->messageBox( tr( "Database is closed"), this );

        if( manApplet->isPRO() )
            addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_LOGOUT, "" );

    }
}

void MainWindow::quit()
{
    manApplet->exitApp();
}


void MainWindow::newKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    NewKeyDlg newKeyDlg;
    newKeyDlg.exec();
}

void MainWindow::makeRequest()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    DBMgr* dbMgr = manApplet->dbMgr();

    MakeReqDlg makeReqDlg;
    makeReqDlg.exec();
}

void MainWindow::makeRequestSetKeyName()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }


    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    KeyPairRec keyRec;
    manApplet->dbMgr()->getKeyPairRec( num, keyRec );

    MakeReqDlg makeReqDlg;
    makeReqDlg.setKeyNum( num );
    makeReqDlg.exec();
}

void MainWindow::makeCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.exec();
}

void MainWindow::makeCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }


    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.exec();
}

void MainWindow::editCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCertProfileDlg makeCertProfileDlg;
    makeCertProfileDlg.setEdit(num);

    makeCertProfileDlg.exec();
}

void MainWindow::viewCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ViewCertProfileDlg viewCertProfile;
    viewCertProfile.setProfile( num );
    viewCertProfile.exec();
}

void MainWindow::copyCertProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.setEdit(num);
    makeCRLProfileDlg.exec();
}

void MainWindow::viewCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    /*
    MakeCRLProfileDlg makeCRLProfileDlg;
    makeCRLProfileDlg.setEdit(num);
    makeCRLProfileDlg.setReadOnly();
    makeCRLProfileDlg.exec();
    */
    ViewCRLProfileDlg viewCRLProfile;
    viewCRLProfile.setProfile( num );
    viewCRLProfile.exec();
}

void MainWindow::copyCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
            makeCertDlg.setIssuer( pItem->getDataNum() );
        }
    }

    makeCertDlg.exec();
}


void MainWindow::makeCRL()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
    if( pItem == NULL )
    {
        manApplet->warningBox( tr( "No items selected" ), this );
        return;
    }

    MakeCRLDlg makeCRLDlg;

    if( pItem )
    {
        if( pItem->getType() == CM_ITEM_TYPE_CA || pItem->getType() == CM_ITEM_TYPE_SUBCA || pItem->getType() == CM_ITEM_TYPE_ROOTCA )
        {
            makeCRLDlg.setIssuerNum( pItem->getDataNum() );
        }
    }

    makeCRLDlg.exec();
}

void MainWindow::renewCert()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    ManTreeItem *pItem = currentTreeItem();
    if( pItem == NULL )
    {
        manApplet->warningBox( tr( "No items selected" ), this );
        return;
    }

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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 )
    {
        manApplet->warningBox( tr( "There is no certificate selected" ), this );
        return;
    }

    if( right_type_ != RightType::TYPE_CERTIFICATE )
    {
        manApplet->warningBox( tr( "Select a certificate" ), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    UserDlg userDlg;
    userDlg.exec();
}

void MainWindow::registerREGSigner()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int nNum = -1;
    ManTreeItem* item = currentTreeItem();
    if( item ) nNum = item->getDataNum();

    ConfigDlg configDlg;
    if( nNum > 0 ) configDlg.setFixKind( nNum );
    configDlg.exec();
}

void MainWindow::editConfig()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this config?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->dbMgr()->delConfigRec( num );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_DEL_CONFIG, "" );

    createRightConfigList();
}

void MainWindow::serverConfig()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int nNum = -1;
    ManTreeItem* item = currentTreeItem();
    if( item ) nNum = item->getDataNum();

    if( nNum == JS_GEN_KIND_OCSP_SRV )
        OCSPSrv();
    else if( nNum == JS_GEN_KIND_TSP_SRV )
        TSPSrv();
    else if( nNum == JS_GEN_KIND_CMP_SRV )
        CMPSrv();
    else if( nNum == JS_GEN_KIND_REG_SRV )
        RegSrv();
}

void MainWindow::viewCertificate()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr( "There is no CA certificate" ), this );
        return;
    }

    manApplet->dbMgr()->getCertRec( crlRec.getIssuerNum(), caRec );

    JS_BIN_decodeHex( crlRec.getCRL().toStdString().c_str(), &binCRL );
    JS_BIN_decodeHex( caRec.getCert().toStdString().c_str(), &binCA );

    ret = JS_PKI_verifyCRL( &binCRL, &binCA );
    if( ret == 1 )
    {
        manApplet->messageBox( "CRL verification successful", this );
    }
    else
    {
        manApplet->warningBox( QString( "CRL verification failed [%1]" ).arg(ret), this );
    }

end :
    JS_BIN_reset( &binCRL );
    JS_BIN_reset( &binCA );
}

void MainWindow::viewRevokeCert()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    RevokeRec revoke;
    manApplet->dbMgr()->getRevokeRec( num, revoke );

    CertInfoDlg certInfoDlg;
    certInfoDlg.setCertNum( revoke.getCertNum() );
    certInfoDlg.exec();
}

void MainWindow::removeRevokeCert()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    bool bVal = manApplet->yesOrNoBox( tr( "Are you sure to remove?"), this );
    if( bVal == false ) return;

    manApplet->dbMgr()->delRevokeRec( num );
    right_table_->removeRow( row );
}

void MainWindow::viewPriKey()
{
    int ret = 0;
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    QTableWidgetItem* item = right_table_->item( row, 0 );
    QTableWidgetItem* item2 = right_table_->item( row, 2 );
    int num = item->text().toInt();
    QString strAlg = item2->text();


    if( isPKCS11Private( strAlg ) )
    {
        if( manApplet->P11CTX() == NULL )
        {
            manApplet->warningBox( tr("Private key for HSM is not visible [%1]").arg(strAlg), this);
            return;
        }
    }


    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr("Private key for KMS is not visible [%1]").arg(strAlg), this);
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("Private key for HSM is unreadable [%1]").arg(strAlg), this);
        return;
    }

    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr( "Private key for KMS is unreadable [%1]").arg(strAlg), this);
        return;
    }

    BIN binPri = {0,0};

    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

    ExportDlg exportDlg;
    exportDlg.setName( keyPair.getName() );
    exportDlg.setPrivateKey( &binPri );
    exportDlg.exec();

    JS_BIN_reset( &binPri );
}


void MainWindow::exportPubKey()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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

    BIN binPub = {0,0};
    JS_BIN_decodeHex( keyPair.getPublicKey().toStdString().c_str(), &binPub );

    ExportDlg exportDlg;
    exportDlg.setName( keyPair.getName() );
    exportDlg.setPublicKey( &binPub );
    exportDlg.exec();

    JS_BIN_reset( &binPub );
}

void MainWindow::exportRequest()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    DBMgr* dbMgr = manApplet->dbMgr();
    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    ReqRec req;
    dbMgr->getReqRec( num, req );

    BIN binCSR = {0,0};

    JS_BIN_decodeHex( req.getCSR().toStdString().c_str(), &binCSR );

    ExportDlg exportDlg;
    exportDlg.setName( req.getName() );
    exportDlg.setCSR( &binCSR );
    exportDlg.exec();

    JS_BIN_reset( &binCSR );
}

void MainWindow::exportCertificate()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    DBMgr* dbMgr = manApplet->dbMgr();
    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    CertRec cert;
    dbMgr->getCertRec( num, cert );

    BIN binCert = {0,0};
    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    JS_BIN_decodeHex( cert.getCert().toStdString().c_str(), &binCert );

    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    ExportDlg exportDlg;
    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setCert( &binCert );
    exportDlg.exec();

    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void MainWindow::exportCRL()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    int row = right_table_->currentRow();
    if( row < 0 ) return;

    DBMgr* dbMgr = manApplet->dbMgr();
    QTableWidgetItem* item = right_table_->item( row, 0 );
    int num = item->text().toInt();

    BIN binCRL = {0,0};
    JCRLInfo sCRLInfo;

    CRLRec crl;
    dbMgr->getCRLRec( num, crl );
    JS_BIN_decodeHex( crl.getCRL().toStdString().c_str(), &binCRL );

    memset( &sCRLInfo, 0x00, sizeof(sCRLInfo));
    JS_PKI_getCRLInfo( &binCRL, &sCRLInfo, NULL, NULL );

    ExportDlg exportDlg;
    exportDlg.setName( sCRLInfo.pIssuerName );
    exportDlg.setCRL( &binCRL );
    exportDlg.exec();

    JS_BIN_reset( &binCRL );
    JS_PKI_resetCRLInfo( &sCRLInfo );
}

void MainWindow::exportPriKeyAndCert()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("can not read PKCS11 private key:%1").arg(strAlg), this);
        return;
    }

    if( strAlg.contains( "KMIP" ) )
    {
        manApplet->warningBox( tr("can not read KMIP private key:%1").arg(strAlg), this);
        return;
    }

    BIN binPri = {0,0};
    BIN binCert = {0,0};

    JCertInfo sCertInfo;

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );

    ExportDlg exportDlg;
    exportDlg.setName( sCertInfo.pSubjectName );
    exportDlg.setPriKeyAndCert( num, &binPri, &binCert );
    exportDlg.exec();

    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binCert );
    JS_PKI_resetCertInfo( &sCertInfo );
}

void MainWindow::setPasswd()
{
    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr->isOpen() == false )
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

    /*
    if( nKeyCount > 0 )
    {
        manApplet->warningBox( tr( "KeyPair has to be empty"), this );
        return;
    }
    */

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

    manApplet->log( QString("Total KeyPair Count: %1").arg( nKeyCount) );
    if( nKeyCount > 0 )
    {
        int ret = 0;
        int nLeftCount = nKeyCount;
        int nLimit = 10;
        int nOffset = 0;
        int nKMIPCount = 0;
        int nPKCS11Count = 0;
        int nCount = 0;
        int nFail = 0;

        while( nLeftCount > 0 )
        {
            QList<KeyPairRec> keyPairList;

            ret = dbMgr->getKeyPairList( -1, nOffset, nLimit, keyPairList );

            for( int i = 0; i < keyPairList.size(); i++ )
            {
                KeyPairRec keyPair = keyPairList.at(i);
                QString strKeyAlg = keyPair.getAlg();

                if( isKMIPPrivate( strKeyAlg ) )
                {
                    manApplet->log( QString( "KeyNum(%1) is KIMP Private and Skip" ).arg( keyPair.getNum() ));
                    nKMIPCount++;
                }
                else if( isPKCS11Private( strKeyAlg ))
                {
                    manApplet->log( QString( "KeyNum(%1) is PKCS11 Private and Skip" ).arg( keyPair.getNum() ));
                    nPKCS11Count++;
                }
                else if( isInternalPrivate( strKeyAlg ) )
                {
                    BIN binPri = {0,0};
                    JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri);
                    QString strEncPri = manApplet->getEncPriHex( &binPri );
                    if( strEncPri.length() < 1 )
                    {
                        manApplet->elog( QString( "KeyNum(%1) is fail to encrypt").arg( keyPair.getNum() ));
                        nFail++;
                    }
                    else
                    {
                        ret = dbMgr->modKeyPairPrivate( keyPair.getNum(), strEncPri );
                        manApplet->log( QString( "KeyNum(%1) is encrypted").arg( keyPair.getNum() ));
                        nCount++;
                    }

                    JS_BIN_reset( &binPri );
                }
            }

            nOffset += keyPairList.size();
            nLeftCount -= keyPairList.size();
            keyPairList.clear();
        }

        manApplet->log( QString("Set Password KeyPair Total(%1) KMIP(%2) PKCS11(%3) Encrypt(%4) Fail(%5)" )
                        .arg( nKeyCount ).arg( nKMIPCount ).arg( nPKCS11Count ).arg( nCount ).arg( nFail ) );
    }

    manApplet->messageBox( tr( "Set Password successfully" ), this );
}

void MainWindow::changePasswd()
{
    QString strOldPass;
    QString strNewPass;

    DBMgr* dbMgr = manApplet->dbMgr();

    if( dbMgr->isOpen() == false )
    {
        manApplet->warningBox( tr( "Database is not opened" ), this );
        return;
    }

    if( manApplet->isPasswd() == false )
    {
        manApplet->warningBox( tr( "The PrivateKeys are not encrypted."), this );
        return;
    }

    if( manApplet->isLicense() == false )
    {
        manApplet->warningBox( tr( "There is no license"), this );
        return;
    }

    LoginDlg loginDlg;
    if( loginDlg.exec() != QDialog::Accepted )
    {
//        manApplet->warningBox( tr( "fail to login" ), this );
        return;
    }

    strOldPass = loginDlg.getPasswd();

    SetPassDlg setPassDlg;
    setPassDlg.mUsePasswdCheck->setEnabled(false);

    if( setPassDlg.exec() != QDialog::Accepted )
    {
        manApplet->warningBox( tr( "fail to set new password" ), this );
        return;
    }

    strNewPass = setPassDlg.getPasswd();
    QString strHMAC = getPasswdHMAC( strNewPass );
    dbMgr->modConfigRec( JS_GEN_KIND_CERTMAN, "Passwd", strHMAC );

    manApplet->setPasswdKey( strNewPass );

    int nKeyCount = manApplet->dbMgr()->getKeyPairCountAll();

    manApplet->log( QString("Total KeyPair Count: %1").arg( nKeyCount) );

    if( nKeyCount > 0 )
    {
        int ret = 0;
        int nLeftCount = nKeyCount;
        int nLimit = 10;
        int nOffset = 0;
        int nKMIPCount = 0;
        int nPKCS11Count = 0;
        int nCount = 0;
        int nFail = 0;

        while( nLeftCount > 0 )
        {
            QList<KeyPairRec> keyPairList;

            ret = dbMgr->getKeyPairList( -1, nOffset, nLimit, keyPairList );

            for( int i = 0; i < keyPairList.size(); i++ )
            {
                KeyPairRec keyPair = keyPairList.at(i);
                QString strKeyAlg = keyPair.getAlg();

                if( isKMIPPrivate( strKeyAlg ) )
                {
                    manApplet->log( QString( "KeyNum(%1) is KIMP Private and Skip" ).arg( keyPair.getNum() ));
                    nKMIPCount++;
                }
                else if( isPKCS11Private( strKeyAlg ))
                {
                    manApplet->log( QString( "KeyNum(%1) is PKCS11 Private and Skip" ).arg( keyPair.getNum() ));
                    nPKCS11Count++;
                }
                else if( isInternalPrivate( strKeyAlg ) )
                {
                    BIN binPri = {0,0};
                    ret = manApplet->getDecPriBIN( strOldPass, keyPair.getPrivateKey(), &binPri );
                    if( ret != 0 )
                    {
                        manApplet->elog( QString( "KeyNum(%1) is fail to decrypt" ).arg( keyPair.getNum() ));
                        JS_BIN_reset( &binPri );
                        nFail++;
                        continue;
                    }

                    QString strEncPri = manApplet->getEncPriHex( &binPri );
                    if( strEncPri.length() < 1 )
                    {
                        manApplet->elog( QString( "KeyNum(%1) is fail to encrypt" ).arg( keyPair.getNum() ));
                        JS_BIN_reset( &binPri );
                        nFail++;
                        continue;
                    }
                    else
                    {
                        ret = dbMgr->modKeyPairPrivate( keyPair.getNum(), strEncPri );
                        manApplet->log( QString( "KeyNum(%1) is changed").arg( keyPair.getNum() ));
                        nCount++;
                    }

                    JS_BIN_reset( &binPri );
                }
            }

            nOffset += keyPairList.size();
            nLeftCount -= keyPairList.size();
            keyPairList.clear();
        }

        manApplet->log( QString("KeyPair Total(%1) KMIP(%2) PKCS11(%3) Change(%4) Fail(%5)" )
                        .arg( nKeyCount ).arg( nKMIPCount ).arg( nPKCS11Count ).arg( nCount ).arg( nFail ) );
    }

    manApplet->messageBox( tr( "Change Password successfully" ), this );

}

void MainWindow::publishLDAP()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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

void MainWindow::getURI()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    GetURIDlg getURIDlg;
    getURIDlg.exec();
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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this certificate profile?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->dbMgr()->delCertProfile( num );
    manApplet->dbMgr()->delCertProfileExtensionList( num );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_DEL_CERT_PROFILE, "" );

    createRightCertProfileList();
}

void MainWindow::deleteCRLProfile()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this CRL profile?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    manApplet->dbMgr()->delCRLProfile( num );
    manApplet->dbMgr()->delCRLProfileExtensionList( num );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_DEL_CRL_PROFILE, "" );

    createRightCRLProfileList();
}

void MainWindow::deleteCertificate()
{
    DBMgr* dbMgr = manApplet->dbMgr();

    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
#if 0
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
#endif
    }

    dbMgr->delCertRec( num );
    manApplet->log( QString( "CertNum : %1 is deleted").arg( num ));
    if( cert.isCA() ) manApplet->mainWindow()->refreshRootCA();

    createRightCertList( cert.getIssuerNum() );
}

void MainWindow::deleteCRL()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
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
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    bool bVal = manApplet->yesOrCancelBox( tr( "Are you sure to delete this user?" ), this, false );
    if( bVal == false ) return;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();
    manApplet->dbMgr()->delUserRec( num );
    manApplet->log( QString("UserNum:%1 is deleted").arg(num));

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_DEL_USER, "" );


    createRightUserList();
}

void MainWindow::deleteSigner()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_DEL_SIGNER, "" );


    createRightSignerList( signer.getType() );
}

void MainWindow::registerAdmin()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    AdminDlg adminDlg;
    adminDlg.exec();
}

void MainWindow::editAdmin()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
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

void MainWindow::useLog( bool bEnable )
{
    text_tab_->setTabEnabled( 1, bEnable );
}

void MainWindow::log( const QString strLog, QColor cr )
{
    if( log_halt_ == true ) return;
    if( text_tab_->isTabEnabled( 1 ) == false ) return;

    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;

    QTextCursor cursor = log_text_->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );
    cursor.insertText( strMsg );

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
    info_text_->update();
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
    JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
    JS_KMS_decodeActivateRsp( &binRsp, &pUUID );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    if( pUUID ) JS_free( pUUID );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth ) JS_KMS_resetAuthentication( pAuth );

    if( ret != 0 )
        manApplet->warningBox( tr("Key activation failed" ), this );
    else
    {
        manApplet->messageBox( tr( "Key activation was successful" ), this );
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
    JS_KMS_sendReceiveSSL( pSSL, &binReq, &binRsp );
    JS_KMS_decodeDestroyRsp( &binRsp );

end :
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pSSL ) JS_SSL_clear( pSSL );
    if( pCTX ) JS_SSL_finish( &pCTX );
    if( pAuth ) JS_KMS_resetAuthentication( pAuth );

    if( ret != 0 )
        manApplet->warningBox( tr("Failed to delete key" ), this );
    else
    {
        manApplet->messageBox( tr( "Key deletion was successful." ), this );
        createRightKMSList();
    }
}

#ifdef USE_CMP

void MainWindow::issueCMP()
{
    int ret = 0;
    int nKeySeq = 0;
    BINList *pTrustList = NULL;
    BIN binRefNum = {0,0};
    BIN binAuthCode = {0,0};
    BIN binPri = {0,0};
    BIN binPub = {0,0};

    BIN binCert = {0,0};
    JNameValList    *pInfoList = NULL;
    JNameValList    *pCurList = NULL;

    QString strAlg;
    QString strParam;
    QString strKeyGen;

    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();

    if( manApplet->settingsMgr()->CMPUse() == false )
    {
        manApplet->warningBox( tr( "There are no CMP settings" ), this );
        return;
    }

    CMPSetTrustList( manApplet->settingsMgr(), &pTrustList );
    UserRec userRec;
    manApplet->dbMgr()->getUserRec( num, userRec );

    if( userRec.getAuthCode().length() < 1 )
    {
        manApplet->warningBox( tr( "There is no AuthNum" ), this );
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
    if( ret != 0 )
    {
        manApplet->elog( QString( "CMP's GENM execution fails [%1]").arg( ret ));
        goto end;
    }

    pCurList = pInfoList;

    while( pCurList )
    {
        QString strName = pCurList->sNameVal.pName;
        QString strValue = pCurList->sNameVal.pValue;

        manApplet->log( QString( "%1 = %2" ).arg( strName ).arg( strValue ));

        if( strName == OBJ_nid2sn( NID_id_regInfo) )
        {
            QStringList freeList = strValue.split( "&" );

            for( int i = 0; i < freeList.size(); i++ )
            {
                QString strOne = freeList.at(i);
                QStringList typeVal = strOne.split( "=" );
                if( typeVal.size() < 2 ) continue;

                QString strType = typeVal.at(0);
                QString strVal = typeVal.at(1);

                if( strType == "alg" )
                    strAlg = strVal;
                else if( strType == "param" )
                    strParam = strVal;
                else if( strType == "keygen" )
                    strKeyGen = strVal;
            }
        }
        else
        {

        }

        pCurList = pCurList->pNext;
    }

    if( strAlg == "RSA" )
    {
        ret = JS_PKI_RSAGenKeyPair( strParam.toInt(), 65537, &binPub, &binPri );
    }
    else if( strAlg == "ECDSA" || strAlg == "SM2" )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binPri );
    }
    else if( strAlg == "DSA" )
    {
        ret = JS_PKI_DSA_GenKeyPair( strParam.toInt(), &binPub, &binPri );
    }
    else if( strAlg == "EdDSA" )
    {
        int nParam = 0;
        if( strParam == "Ed448" )
            nParam = JS_EDDSA_PARAM_448;
        else
            nParam = JS_EDDSA_PARAM_25519;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binPri );
    }

    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to generate key pair: %1" ).arg(ret ));
        goto end;
    }

    nKeySeq = saveKeyPair( userRec.getName().toStdString().c_str(), &binPub, &binPri  );
    if( nKeySeq < 0 )
    {
        manApplet->elog( QString( "failed to save keypair: %1").arg( nKeySeq ));
        ret = -1;
        goto end;
    }

    ret = JS_CMP_clientIR( strURL.toStdString().c_str(), pTrustList, strDN.toStdString().c_str(), &binRefNum, &binAuthCode, &binPri, 0, &binCert );
    if( ret != 0 )
    {
        manApplet->elog( QString( "CMP's IR execution fails [%1]").arg( ret ));
        goto end;
    }

    ret = writeCertDB( manApplet->dbMgr(), &binCert );

end:
    if( ret == 0 )
    {
        manApplet->messageBox( tr("The certificate was issued by CMP." ), this );
    }
    else
    {
        manApplet->warningBox( tr( "The certificate could not be issued through CMP [%1]" ).arg(ret), this );
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
    int nKeySeq = 0;
    BINList *pTrustList = NULL;
    JNameValList    *pInfoList = NULL;
    JNameValList    *pCurList = NULL;

    QString strAlg;
    QString strParam;
    QString strKeyGen;

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
        manApplet->warningBox( tr( "There are no CMP settings" ), this );
        return;
    }

    CMPSetTrustList( manApplet->settingsMgr(), &pTrustList );
    CertRec certRec;
    manApplet->dbMgr()->getCertRec( num, certRec );

    if( certRec.getKeyNum() <= 0 )
    {
        manApplet->warningBox( tr("There is no key pair information."), this );
        return;
    }

    KeyPairRec keyPair;
    manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );

    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

    QString strURL = manApplet->settingsMgr()->CMPURI();
    strURL += "/CMP";
    QString strCAPath = manApplet->settingsMgr()->CMPCACertPath();

    JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCACert );

    ret = JS_CMP_clientUpdateGENM( strURL.toStdString().c_str(), pTrustList, &binCert, &binPri, &pInfoList );
    if( ret != 0 )
    {
        manApplet->elog( QString( "CMP's GENM execution fails [%1]").arg( ret ));
        goto end;
    }

    pCurList = pInfoList;

    while( pCurList )
    {
        QString strName = pCurList->sNameVal.pName;
        QString strValue = pCurList->sNameVal.pValue;

        manApplet->log( QString( "%1 = %2" ).arg( strName ).arg( strValue ));

        if( strName == "FreeText" )
        {
            QStringList freeList = strValue.split( "&" );

            for( int i = 0; i < freeList.size(); i++ )
            {
                QString strOne = freeList.at(i);
                QStringList typeVal = strOne.split( "=" );
                if( typeVal.size() < 2 ) continue;

                QString strType = typeVal.at(0);
                QString strVal = typeVal.at(1);

                if( strType == "alg" )
                    strAlg = strVal;
                else if( strType == "param" )
                    strParam = strVal;
                else if( strType == "keygen" )
                    strKeyGen = strVal;
            }
        }
        else
        {

        }

        pCurList = pCurList->pNext;
   }

    if( strAlg == "RSA" )
    {
        ret = JS_PKI_RSAGenKeyPair( strParam.toInt(), 65537, &binPub, &binNewPri );
    }
    else if( strAlg == "ECDSA" || strAlg == "SM2" )
    {
        ret = JS_PKI_ECCGenKeyPair( strParam.toStdString().c_str(), &binPub, &binNewPri );
    }
    else if( strAlg == "DSA" )
    {
        ret = JS_PKI_DSA_GenKeyPair( strParam.toInt(), &binPub, &binNewPri );
    }
    else if( strAlg == "EdDSA" )
    {
        int nParam = 0;
        if( strParam == "Ed448" )
            nParam = JS_EDDSA_PARAM_448;
        else
            nParam = JS_EDDSA_PARAM_25519;

        ret = JS_PKI_EdDSA_GenKeyPair( nParam, &binPub, &binNewPri );
    }

    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to generate key pair: %1" ).arg(ret ));
        goto end;
    }

    nKeySeq = saveKeyPair( certRec.getSubjectDN().toStdString().c_str(), &binPub, &binNewPri );
    if( nKeySeq < 0 )
    {
        manApplet->elog( QString( "failed to save keypair: %1").arg( nKeySeq ));
        goto end;
    }

    ret = JS_CMP_clientKUR( strURL.toStdString().c_str(), pTrustList, &binCACert, &binCert, &binPri, &binNewPri, 0, &binNewCert );
    if( ret != 0 )
    {
        manApplet->elog( QString( "CMP's KUR execution fails [%1]").arg( ret ));
        goto end;
    }

    ret = writeCertDB( manApplet->dbMgr(), &binNewCert );

end :
    if( ret == 0 )
    {
        manApplet->messageBox( tr("The certificate was updated by CMP." ), this );
        manApplet->mainWindow()->createRightCertList( certRec.getIssuerNum() );
    }
    else
    {
        manApplet->warningBox( tr( "The certificate could not be updated through CMP [%1]" ).arg(ret), this );
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
        manApplet->warningBox( tr( "There are no CMP settings" ), this );
        return;
    }

    CMPSetTrustList( manApplet->settingsMgr(), &pTrustList );
    CertRec certRec;
    manApplet->dbMgr()->getCertRec( num, certRec );
    KeyPairRec keyPair;

    if( certRec.getKeyNum() <= 0 )
    {
        manApplet->warningBox(tr("There is no key pair information."), this );
        return;
    }

    manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );


    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

    QString strURL = manApplet->settingsMgr()->CMPURI();
    strURL += "/CMP";
    QString strCAPath = manApplet->settingsMgr()->CMPCACertPath();

    JS_BIN_fileReadBER( strCAPath.toLocal8Bit().toStdString().c_str(), &binCACert );

    ret = JS_CMP_clientRR( strURL.toStdString().c_str(), pTrustList, &binCACert, &binCert, &binPri, nReason );
    if( ret != 0 )
    {
        manApplet->elog( QString( "CMP's RR execution fails [%1]").arg( ret ));
        goto end;
    }

end :
    if( ret == 0 )
    {
        manApplet->messageBox( tr("The certificate was revoked by CMP." ), this );
        manApplet->mainWindow()->createRightCertList( certRec.getIssuerNum() );
    }
    else
    {
        manApplet->warningBox( tr( "The certificate could not be revoked through CMP [%1]" ).arg(ret), this );
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
        manApplet->messageBox( tr( "MAC verification successful" ), this );
    else
        manApplet->warningBox( tr( "MAC verification failed" ), this );
}

void MainWindow::viewTSTInfo()
{
    int ret = 0;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );
    if( item == NULL ) return;

    int num = item->text().toInt();

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    TSPRec tspRec;
    BIN binTST = {0,0};
    dbMgr->getTSPRec( num, tspRec );
    JS_BIN_decodeHex( tspRec.getTSTInfo().toStdString().c_str(), &binTST );


    TSTInfoDlg tstInfoDlg;
    tstInfoDlg.setTST( &binTST );
    JS_BIN_reset( &binTST );
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
    if( item == NULL ) return;

    int num = item->text().toInt();

    TSPRec tspRec;
    manApplet->dbMgr()->getTSPRec( num, tspRec );
    JS_BIN_decodeHex( tspRec.getData().toStdString().c_str(), &binTS );


    SettingsMgr *smgr = manApplet->settingsMgr();
    if( smgr )
    {
        if( smgr->TSPUse() )
        {
            JS_BIN_fileReadBER( smgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binCert );
        }
    }

    ret = JS_PKCS7_verifySignedData( &binTS, &binCert, &binData );
    QString strVerify = QString( "SignedData verification result : %1" ).arg( ret );

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

    if( smgr->SCEPUse() == false )
    {
        manApplet->warnLog( tr( "There are no SCEP settings" ), this );
        return;
    }

    QString strSCEPURL = smgr->SCEPURI();
    QString strURL;

    if( smgr->SCEPMutualAuth() )
    {
        QString strCertPath = smgr->SCEPCertPath();
        QString strPriPath = smgr->SCEPPriKeyPath();

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binSSLCert );
        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binSSLPri );
    }

    JS_PKI_genRandom( 16, &binSenderNonce );
    JS_SCEP_makeTransID( &binCSR, &pTransID );

    strURL = QString( "%1/pkiclient.exe?operation=GetCACert" ).arg( strSCEPURL );

    nRet = JS_HTTP_requestGetBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                &nStatus,
                &binCACert );

    if( nRet != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        manApplet->warnLog( QString( "failed to request HTTP get [%1:%2]").arg(nRet).arg(nStatus), this);
        goto end;
    }

    JS_BIN_decodeHex( req.getCSR().toStdString().c_str(), &binCSR );

    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

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
        manApplet->warnLog( QString("failed to make PKIReq [%1]").arg(nRet), this );
        goto end;
    }

    strURL = QString( "%1/pkiclient.exe?operation=PKIOperation").arg( strSCEPURL );

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
        manApplet->warnLog( QString( "failed to request HTTP post [%1:%2]" ).arg( nRet ).arg( nStatus ), this );
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
        manApplet->warnLog( QString( "failed to parse CertRsp" ), this );
        goto end;
    }

    nRet = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNewCert );
    if( nRet != 0 )
    {
        manApplet->warnLog( QString("failed to get sign certificate with SCEP [%1]").arg( nRet ), this );
        goto end;
    }

    nRet = writeCertDB( manApplet->dbMgr(), &binNewCert );
    if( nRet == 0 )  manApplet->dbMgr()->modReqStatus( num, 1 );

    if( nRet == 0 ) manApplet->messageLog( tr( "The certificate was issued by SCEP."), this );
    manApplet->mainWindow()->createRightCertList( kImportNum );

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
    int nCSRNum = -1;

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

    if( smgr->SCEPUse() == false )
    {
        manApplet->warnLog( tr( "There are no SCEP settings" ), this );
        return;
    }

    QString strSCEPURL = smgr->SCEPURI();
    QString strURL;

    CertRec certRec;
    KeyPairRec keyPair;

    manApplet->dbMgr()->getCertRec( num, certRec );

    memset( &sCertInfo, 0x00, sizeof(sCertInfo));

    if( certRec.getKeyNum() < 0 )
    {
        manApplet->warningBox( tr( "The certificate has not keypair data"), this );
        goto end;
    }

    manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );

    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );
    ret = JS_PKI_getCertInfo( &binCert, &sCertInfo, NULL );
    if( ret !=  0)
    {
        manApplet->warningBox( tr("failed to decode a certificate [%1]").arg(ret), this );
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
    else if( nKeyType == JS_PKI_KEY_TYPE_DSA )
    {
        ret = JS_PKI_DSA_GenKeyPair( nOption, &binPub, &binPri );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_EDDSA )
    {
        ret = JS_PKI_EdDSA_GenKeyPair( nOption, &binPub, &binPri );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( tr( "failed to generate keypair [%1]").arg(ret), this );
        goto end;
    }

    nKeyNum = saveKeyPair( sCertInfo.pSubjectName, &binNPub, &binNPri );
    if( nKeyNum < 0 )
    {
        manApplet->warnLog( tr( "failed to save keypair [%1]" ).arg(ret), this );
        goto end;
    }

    ret = JS_PKI_makeCSR( "SHA256", sCertInfo.pSubjectName, pChallengePass, NULL, &binNPri, NULL, &binCSR );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "failed to make CSR [%1]").arg(ret), this );
        goto end;
    }

    nCSRNum = writeCSRDB( manApplet->dbMgr(), nKeyNum, "SCEP Update", sCertInfo.pSubjectName, "SHA256", &binCSR );
    if( nCSRNum < 0 )
    {
        manApplet->warnLog( tr( "failed to save CSR" ), this );
        goto end;
    }

    manApplet->dbMgr()->modKeyPairStatus( nKeyNum, 1 );

    if( smgr->SCEPMutualAuth() )
    {
        QString strCertPath = smgr->SCEPCertPath();
        QString strPriPath = smgr->SCEPPriKeyPath();

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binSSLCert );
        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binSSLPri );
    }

    JS_PKI_genRandom( 16, &binSenderNonce );
    JS_SCEP_makeTransID( &binCSR, &pTransID );

    strURL = QString( "%1/pkiclient.exe?operation=GetCACert" ).arg( strSCEPURL );

    ret = JS_HTTP_requestGetBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                &nStatus,
                &binCACert );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        manApplet->warnLog( QString("failed to request HTTP get [%1:%2]").arg(ret).arg(nStatus), this );
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
        manApplet->warnLog( QString("failed to make PKIReq : %1").arg( ret ), this );
        goto end;
    }

    strURL = QString( "%1/pkiclient.exe?operation=PKIOperation").arg( strSCEPURL );

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
        manApplet->warningBox( QString("failed to request HTTP post [%1:%2]").arg(ret).arg(nStatus), this );
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
        manApplet->warnLog( QString("failed to parse CertRsp : %1").arg(ret), this );
        goto end;
    }

    ret = JS_SCEP_getSignCert( &binSignedData, &binCSR, &binNCert );
    if( ret != 0 )
    {
        manApplet->warnLog( QString("failed to get sign certificate in reply: %1").arg(ret), this );
        goto end;
    }

    writeCertDB( manApplet->dbMgr(), &binNCert );
    manApplet->dbMgr()->modReqStatus( nCSRNum, 1 );

    if( ret == 0 ) manApplet->messageLog( tr( "The certificate was renewed by SCEP"), this );

    manApplet->mainWindow()->createRightCertList( kImportNum );

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

    if( smgr->SCEPUse() == false )
    {
        manApplet->warnLog( tr( "There are no SCEP settings" ), this );
        return;
    }

    QString strSCEPURL = smgr->SCEPURI();
    QString strURL;

    CertRec certRec;
    KeyPairRec keyPair;

    manApplet->dbMgr()->getCertRec( num, certRec );

    if( certRec.getKeyNum() < 0 )
    {
        manApplet->warningBox( tr( "The certificate has not keypair data"), this );
        goto end;
    }

    manApplet->dbMgr()->getKeyPairRec( certRec.getKeyNum(), keyPair );


    manApplet->getPriKey( keyPair.getPrivateKey(), &binPri );

    JS_BIN_decodeHex( certRec.getCert().toStdString().c_str(), &binCert );

    if( smgr->SCEPMutualAuth() )
    {
        QString strCertPath = smgr->SCEPCertPath();
        QString strPriPath = smgr->SCEPPriKeyPath();

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binSSLCert );
        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binSSLPri );
    }

    JS_PKI_genRandom( 16, &binSenderNonce );


    strURL = QString( "%1/pkiclient.exe?operation=GetCACert" ).arg( strSCEPURL );

    ret = JS_HTTP_requestGetBin2(
                strURL.toStdString().c_str(),
                &binSSLPri,
                &binSSLCert,
                &nStatus,
                &binCACert );

    if( ret != 0 || nStatus != JS_HTTP_STATUS_OK )
    {
        manApplet->warnLog( QString("failed to request HTTP get [%1:%2]").arg(ret).arg( nStatus ), this );
        goto end;
    }

    ret = JS_SCEP_makeGetCRL( &binCert, &binPri, &binCert, &binCACert, &binSenderNonce, pTransID, &binReq );

    if( ret != 0 )
    {
        manApplet->warnLog( QString( "failed to make GetCRL: %1" ).arg( ret ), this );
        goto end;
    }

    strURL = QString( "%1/pkiclient.exe?operation=PKIOperation").arg( strSCEPURL );

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
        manApplet->warningBox( QString("fail to request HTTP post [%1:%2]").arg(ret).arg(nStatus), this );
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
        manApplet->warnLog( QString("failed to parse CertRsp : %1").arg(ret), this );
        goto end;
    }

    ret = JS_SCEP_getCRL( &binSignedData, &binCRL );
    if( ret != 0 )
    {
        manApplet->warningBox( QString("failed to get CRL with SCEP: %1").arg(ret), this );
        goto end;
    }

    writeCRLDB( manApplet->dbMgr(), &binCRL );

    if( ret == 0 ) manApplet->messageLog( tr( "The getCRL was successful with SCEP"), this );

    manApplet->mainWindow()->createRightCRLList( kImportNum );

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

void MainWindow::toggleLog()
{
    if( log_halt_ == true )
    {
        log_halt_ = false;
        log( "Log is activated" );
    }
    else
    {
        log( "Log is halt" );
        log_halt_ = true;
    }
}

void MainWindow::CAMan()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    ca_man_dlg_->show();
    ca_man_dlg_->raise();
    ca_man_dlg_->activateWindow();
}

void MainWindow::profileMan()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    profile_man_dlg_->show();
    profile_man_dlg_->raise();
    profile_man_dlg_->activateWindow();
}

void MainWindow::OCSPSrv()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    if( pki_srv_ == NULL ) return;
    pki_srv_->setSrvKind( JS_GEN_KIND_OCSP_SRV );
    pki_srv_->show();
    pki_srv_->raise();
    pki_srv_->activateWindow();
}

void MainWindow::TSPSrv()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    if( pki_srv_ == NULL ) return;
    pki_srv_->setSrvKind( JS_GEN_KIND_TSP_SRV );
    pki_srv_->show();
    pki_srv_->raise();
    pki_srv_->activateWindow();
}

void MainWindow::CMPSrv()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    if( pki_srv_ == NULL ) return;
    pki_srv_->setSrvKind( JS_GEN_KIND_CMP_SRV );
    pki_srv_->show();
    pki_srv_->raise();
    pki_srv_->activateWindow();
}

void MainWindow::RegSrv()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    if( pki_srv_ == NULL ) return;
    pki_srv_->setSrvKind( JS_GEN_KIND_REG_SRV );
    pki_srv_->show();
    pki_srv_->raise();
    pki_srv_->activateWindow();
}

void MainWindow::CCSrv()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    if( pki_srv_ == NULL ) return;
    pki_srv_->setSrvKind( JS_GEN_KIND_CC_SRV );
    pki_srv_->show();
    pki_srv_->raise();
    pki_srv_->activateWindow();
}

void MainWindow::KMSSrv()
{
    if( manApplet->isDBOpen() == false )
    {
        manApplet->warningBox( tr("The database is not connected."), this );
        return;
    }

    if( pki_srv_ == NULL ) return;
    pki_srv_->setSrvKind( JS_GEN_KIND_KMS_SRV );
    pki_srv_->show();
    pki_srv_->raise();
    pki_srv_->activateWindow();
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

        int nCACount = manApplet->dbMgr()->getCACount( certRec.getNum() );

        ManTreeItem *pSubCAItem = new ManTreeItem( QString(tr("CA[%1]").arg( nCACount )));
        pSubCAItem->setType( CM_ITEM_TYPE_SUBCA );
        pSubCAItem->setIcon(QIcon(":/images/ca.png"));
        pSubCAItem->setDataNum( certRec.getNum() );
        pCAItem->appendRow( pSubCAItem );

        left_tree_->expand( pCAItem->index() );
    }

    left_tree_->expand( item->index() );
}

void MainWindow::licenseInfo()
{
    LCNInfoDlg lcnInfoDlg;
    if( lcnInfoDlg.exec() == QDialog::Accepted )
    {
//        if( manApplet->yesOrNoBox(tr("The license has been changed. Restart to apply it?"), this, true))
//            manApplet->restartApp();
    }
}

void MainWindow::bugIssueReport()
{
    QString link = "https://github.com/jykim74/CertMan/issues/new";
    QDesktopServices::openUrl(QUrl(link));
}

void MainWindow::qnaDiscussion()
{
//    QString link = "https://github.com/jykim74/CertMan/discussions/new?category=q-a";
    QString link = "https://groups.google.com/g/certman";
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
    int ret = 0;
    QString strStatus;
    int row = right_table_->currentRow();
    QTableWidgetItem* item = right_table_->item( row, 0 );

    int num = item->text().toInt();


    CertRec certRec;
    RevokeRec   revokeRec;
    char        sRevokedDate[64];
    const char  *pReason = NULL;

    ret = manApplet->dbMgr()->getCertRec( num, certRec );

    if( certRec.getNum() <= 0 )
    {
        manApplet->warningBox( tr("fail to get certificate information : %1").arg(ret), this );
        return;
    }

    if( certRec.getStatus() == JS_CERT_STATUS_REVOKE )
    {
        ret = manApplet->dbMgr()->getRevokeRecByCertNum( certRec.getNum(), revokeRec );
        if( revokeRec.getSeq() <= 0 )
        {
            manApplet->warningBox( tr("fail to get revoke information : %1").arg(ret), this );
            return;
        }
    }

    if( certRec.getStatus() == JS_CERT_STATUS_GOOD )
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
        manApplet->warningBox( tr( "There are no OCSP settinsgs" ), this );
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

        JS_BIN_fileReadBER( strCertPath.toLocal8Bit().toStdString().c_str(), &binSignerCert );
        JS_BIN_fileReadBER( strPriPath.toLocal8Bit().toStdString().c_str(), &binSignerPri );

        ret = JS_OCSP_encodeRequest( &binCert, &binCA, "SHA1", &binSignerPri, &binSignerCert, &binReq );
    }
    else
    {
        ret = JS_OCSP_encodeRequest( &binCert, &binCA, "SHA1", NULL, NULL, &binReq );
    }

    if( ret != 0 )
    {
        manApplet->warningBox( QString(tr("failed to encode request: %1")).arg(ret), this );
        goto end;
    }

    strURL = manApplet->settingsMgr()->OCSPURI();
    strURL += "/OCSP";
    strOCSPSrvCert = manApplet->settingsMgr()->OCSPSrvCertPath();

    JS_BIN_fileReadBER( strOCSPSrvCert.toLocal8Bit().toStdString().c_str(), &binSrvCert );

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/ocsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        manApplet->warningBox( tr( "failed to request [%1]").arg(ret), this );
        goto end;
    }


    ret = JS_OCSP_decodeResponse( &binRsp, &binSrvCert, &sIDInfo, &sStatusInfo );
    if( ret != 0 )
    {
        manApplet->warningBox( QString(tr( "failed to decode response:%1" )).arg(ret), this );
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

    QString strToken;

    ret = manApplet->loignRegServer( strToken );
    if( ret != 0 )
    {
        manApplet->warnLog( tr( "failed to login RegServer" ), this );
        return;
    }

    if( mgr->REGUse() == false )
    {
        manApplet->warningBox( tr( "There are no REG settings" ), this );
        return;
    }

    strURL = mgr->REGURI();
    strURL += JS_REG_PATH_CERT_STATUS;

    JS_JSON_encodeRegCertStatusReq( &sStatusReq, &pReq );

    JS_HTTP_requestTokenPost( strURL.toStdString().c_str(),
                            "application/json",
                            strToken.toStdString().c_str(),
                            pReq, &nStatus, &pRsp );

    JS_JSON_decodeRegCertStatusRsp( pRsp, &sStatusRsp );

    if( strcasecmp( sStatusRsp.pResCode, "0000" ) == 0 )
    {
        QString strStatus = sStatusRsp.pStatus;
        manApplet->messageBox( strStatus, this );
        ret = 0;
    }
    else
    {
        manApplet->warningBox( "failed to get certificate status by REGServer", this );
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

    QString strToken;

    ret = manApplet->loignRegServer( strToken );
    if( ret != 0 )
    {
        manApplet->warnLog( tr( "failed to login RegServer" ), this );
        return;
    }

    if( mgr->REGUse() == false )
    {
        manApplet->warningBox( tr( "There are no REG settings" ), this );
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
    strURL += JS_REG_PATH_CERT_REVOKE;

    JS_JSON_setRegCertRevokeReq( &sRevokeReq, "name", cert.getSubjectDN().toStdString().c_str(), "1" );

    JS_JSON_encodeRegCertRevokeReq( &sRevokeReq, &pReq );

    JS_HTTP_requestTokenPost( strURL.toStdString().c_str(),
                            "application/json",
                             strToken.toStdString().c_str(),
                            pReq, &nStatus, &pRsp );

    JS_JSON_decodeRegRsp( pRsp, &sRevokeRsp );

    if( strcasecmp( sRevokeRsp.pResCode, "0000" ) == 0 )
    {
        manApplet->messageBox( tr("The certificate is revoked"), this );
        ret = 0;
    }
    else
    {
        manApplet->warningBox( "failed to revoke certificate by REGServer", this );
        ret = -1;
    }

    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );

    JS_JSON_resetRegCertRevokeReq( &sRevokeReq );
    JS_JSON_resetRegRsp( &sRevokeRsp );
}

void MainWindow::createRightList( int nType, int nNum )
{
#ifdef _ENABLE_CHARTS
    stack_->setCurrentIndex(0);
#endif

    if( nType == CM_ITEM_TYPE_KEYPAIR )
        createRightKeyPairList();
    else if( nType == CM_ITEM_TYPE_REQUEST )
        createRightRequestList();
    else if( nType == CM_ITEM_TYPE_CERT_PROFILE )
        createRightCertProfileList();
    else if( nType == CM_ITEM_TYPE_CRL_PROFILE )
        createRightCRLProfileList();
    else if( nType == CM_ITEM_TYPE_ROOTCA )
        createRightCertList( kSelfNum );
    else if( nType == CM_ITEM_TYPE_IMPORT_CERT )
        createRightCertList( kImportNum );
    else if( nType == CM_ITEM_TYPE_IMPORT_CRL )
        createRightCRLList( kImportNum );
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
        createRightConfigList( nNum );
    else if( nType == CM_ITEM_TYPE_REG_SIGNER )
        createRightSignerList( SIGNER_TYPE_REG );
    else if( nType == CM_ITEM_TYPE_OCSP_SIGNER )
        createRightSignerList( SIGNER_TYPE_OCSP );
    else if( nType == CM_ITEM_TYPE_KMS )
        createRightKMSList();
#ifdef _ENABLE_CHARTS
    else if( nType == CM_ITEM_TYPE_STATISTICS )
        createRightStatistics();
#endif
    else if( nType == CM_ITEM_TYPE_AUDIT )
        createRightAuditList();
    else if( nType == CM_ITEM_TYPE_TSP )
        createRightTSPList();
}

void MainWindow::createRightKeyPairList()
{
    search_form_->show();


    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Algorithm"), tr("Name") };
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

    if( keyPairList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_KEYPAIR;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 ); // Number
    right_table_->setColumnWidth( 1, 130 ); // RegTime
    right_table_->setColumnWidth( 2, 80 );

    for( int i = 0; i < keyPairList.size(); i++ )
    {
        KeyPairRec keyPairRec = keyPairList.at(i);

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg(keyPairRec.getNum() ));

        if( isPKCS11Private( keyPairRec.getAlg() ) )
            seq->setIcon( QIcon( ":/images/hsm.png" ));
        else
            seq->setIcon( QIcon(":/images/key_reg.png" ));

        int nStatus = keyPairRec.getStatus();
        seq->setData( Qt::UserRole, nStatus );

        QTableWidgetItem *item = new QTableWidgetItem( keyPairRec.getName() );
        if( nStatus == JS_REC_STATUS_USED ) item->setIcon( QIcon(":/images/csr.png" ));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( dateString( keyPairRec.getRegTime()))));
        right_table_->setItem( i, 2, new QTableWidgetItem( keyPairRec.getAlg()));
        right_table_->setItem( i, 3, item );
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}


void MainWindow::createRightRequestList()
{
    search_form_->show();

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Hash"), tr("Name") };
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

    if( reqList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_REQUEST;
    removeAllRight();
    right_table_->clear();
    right_table_->clearContents();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);


    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 80 );

    for( int i=0; i < reqList.size(); i++ )
    {
        ReqRec reqRec = reqList.at(i);

        QTableWidgetItem *item = new QTableWidgetItem( reqRec.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( reqRec.getSeq() ));
        seq->setIcon(QIcon(":/images/csr.png"));

        int nStatus = reqRec.getStatus();
        seq->setData( Qt::UserRole, nStatus );

        if( nStatus == JS_REC_STATUS_USED ) item->setIcon( QIcon(":/images/cert.png" ));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( dateString( reqRec.getRegTime()) ) ));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( reqRec.getHash() )));
        right_table_->setItem( i, 3, item );
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightCertProfileList()
{
    search_form_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CERT_PROFILE;

    QStringList headerList = { tr("Num"), tr("NotBefore"), tr("NotAfter"), tr("Hash"), tr("Name") };

    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    QList<CertProfileRec> certProfileList;
    manApplet->dbMgr()->getCertProfileList( certProfileList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 100 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 80 );

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
        getPeriodString( certProfile.getNotBefore(), certProfile.getNotAfter(), strNotBefore, strNotAfter );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( strNotBefore )));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strNotAfter )));
        right_table_->setItem( i, 3, new QTableWidgetItem( certProfile.getHash() ));
        right_table_->setItem( i, 4, item);
    }
}

void MainWindow::createRightCRLProfileList()
{
    search_form_->hide();

    removeAllRight();
    right_type_ = RightType::TYPE_CRL_PROFILE;

    QStringList headerList = { tr("Num"), tr("ThisUpdate"), tr("NextUpdate"), tr("Hash"), tr("Name") };
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);


    QList<CRLProfileRec> crlProfileList;
    manApplet->dbMgr()->getCRLProfileList( crlProfileList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 100 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 80 );

    for( int i=0; i < crlProfileList.size(); i++ )
    {
        CRLProfileRec crlProfile = crlProfileList.at(i);

        QString strThisUpdate;
        QString strNextUpdate;

        QTableWidgetItem *item = new QTableWidgetItem( crlProfile.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( crlProfile.getNum() ));
        seq->setIcon(QIcon(":/images/crl_profile.png"));

        getPeriodString( crlProfile.getThisUpdate(), crlProfile.getNextUpdate(), strThisUpdate, strNextUpdate );

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( strThisUpdate )) );
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( strNextUpdate )) );
        right_table_->setItem( i, 3, new QTableWidgetItem( crlProfile.getHash()) );
        right_table_->setItem( i, 4, item );
    }
}

void MainWindow::createRightCertList( int nIssuerNum, bool bIsCA )
{
    search_form_->show();

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;



    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Algorithm"), tr("SubjectDN") };

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QList<CertRec> certList;


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

    if( certList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_CERTIFICATE;
    removeAllRight();
    right_table_->clear();


    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 120 );

    for( int i=0; i < certList.size(); i++ )
    {
        int pos = 0;
        CertRec cert = certList.at(i);

        QTableWidgetItem *item = new QTableWidgetItem( cert.getSubjectDN() );
        if( cert.isSelf() ) item->setIcon( QIcon( ":/images/self.png" ) );

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( cert.getNum() ));

        if( nIssuerNum == kImportNum )
        {
            seq->setIcon( QIcon(":/images/im_cert.png"));
        }
        else
        {
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
        }

        QString strUserName;

        if( cert.getUserNum() > 0 )
            manApplet->dbMgr()->getNumName( cert.getUserNum(), "TB_USER", "NAME" );
        else
            strUserName = "";

        QString strAlg = cert.getSignAlg();

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, pos++, seq );
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( dateString(cert.getRegTime())  ) ));
        right_table_->setItem( i, pos++, new QTableWidgetItem( QString("%1").arg( strAlg )));
        right_table_->setItem( i, pos++, item );
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightCRLList( int nIssuerNum )
{
    search_form_->show();

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("ThisUpdate"), tr("SignAlg"), tr("CRLDP") };
    QList<CRLRec> crlList;


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

    if( crlList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_CRL;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels( headerList );
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 130 );
    right_table_->setColumnWidth( 3, 90 );

    for( int i=0; i < crlList.size(); i++ )
    {
        CRLRec crl = crlList.at(i);
        QString strIssuerName;
/*
        if( crl.getIssuerNum() >= 0 )
            strIssuerName = manApplet->dbMgr()->getNumName( crl.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
        else if( crl.getIssuerNum() == kImportNum )
            strIssuerName = "Import (None)";
        else
            strIssuerName = "None";
*/

//        QTableWidgetItem *item = new QTableWidgetItem( strIssuerName );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( crl.getNum() ));

        if( nIssuerNum == kImportNum )
        {
            seq->setIcon( QIcon(":/images/im_crl.png"));
        }
        else
        {
            seq->setIcon(QIcon(":/images/crl.png"));
        }

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem( i, 0, seq );
        right_table_->setItem( i, 1, new QTableWidgetItem( QString("%1").arg( dateString(crl.getRegTime()) )));
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg( dateString(crl.getThisUpdate()) )) );
        right_table_->setItem( i, 3, new QTableWidgetItem( crl.getSignAlg() ));
        right_table_->setItem( i, 4, new QTableWidgetItem( crl.getCRLDP() ));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightRevokeList(int nIssuerNum)
{
    search_form_->show();

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Num"), tr("Cert"), tr("Serial"), tr("RevokeDate"), tr("CRLDP") };

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

    if( revokeList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_REVOKE;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 120 );
    right_table_->setColumnWidth( 2, 60 );
    right_table_->setColumnWidth( 3, 130 );

    for( int i=0; i < revokeList.size(); i++ )
    {
        RevokeRec revoke = revokeList.at(i);

        QString strCertName = manApplet->dbMgr()->getNumName( revoke.getCertNum(), "TB_CERT", "SUBJECTDN" );

        QTableWidgetItem *item = new QTableWidgetItem( strCertName );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( revoke.getSeq() ));
        seq->setIcon(QIcon(":/images/revoke.png"));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i, 0, seq );
        right_table_->setItem(i, 1, item );
        right_table_->setItem(i, 2, new QTableWidgetItem(QString("%1").arg(revoke.getSerial())));
        right_table_->setItem(i, 3, new QTableWidgetItem(QString("%1").arg(dateString( revoke.getRevokeDate() ))));
        right_table_->setItem(i, 4, new QTableWidgetItem(QString("%1").arg(revoke.getCRLDP())));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightUserList()
{
    search_form_->show();


    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Status"), tr("Name"), tr("Email") };

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

    if( userList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_USER;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 60 );
    right_table_->setColumnWidth( 3, 180 );


    for( int i = 0; i < userList.size(); i++ )
    {
        UserRec user = userList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );

        QTableWidgetItem *item = new QTableWidgetItem( user.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( user.getNum() ));

        seq->setIcon(QIcon(":/images/user.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( dateString( user.getRegTime() ) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getUserStatusName( user.getStatus() ) )));
        right_table_->setItem(i,3, item);
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( user.getEmail() )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightKMSList()
{
    search_form_->show();


    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Status"), tr("Type"), tr("Algorithm") };

    QList<KMSRec> kmsList;

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

    if( kmsList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_KMS;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 100 );


    for( int i = 0; i < kmsList.size(); i++ )
    {
        KMSRec kms = kmsList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );

        QString strType = JS_KMS_getObjectTypeName( kms.getType() );
        QString strAlgorithm = JS_PKI_getKeyAlgName( kms.getAlgorithm() );

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( kms.getSeq() ));
        seq->setIcon(QIcon(":/images/kms.png"));

        right_table_->setItem(i,0, seq);
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( dateString( kms.getRegTime() ) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getStatusName( kms.getState() ))));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( strType )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( strAlgorithm )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightSignerList(int nType)
{
    search_form_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_SIGNER;

    QStringList headerList = { tr("Num"), tr("RegTime"), tr("Type"), tr("Status"), tr("DN")  };

    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<SignerRec> signerList;
    manApplet->dbMgr()->getSignerList( nType, signerList );


    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 80 );
    right_table_->setColumnWidth( 3, 80 );

    for( int i = 0; i < signerList.size(); i++ )
    {
        SignerRec signer = signerList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );

        QTableWidgetItem *item = new QTableWidgetItem( signer.getDN() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( signer.getNum() ));

        if( nType == SIGNER_TYPE_REG )
            seq->setIcon(QIcon(":/images/reg_signer.png"));
        else if( nType == SIGNER_TYPE_OCSP )
            seq->setIcon(QIcon(":/images/ocsp_signer.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( dateString( signer.getRegTime()) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( getSignerTypeName( signer.getType() ))));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( getStatusName( signer.getStatus() ))));
        right_table_->setItem(i,4, item );
    }
}

void MainWindow::createRightAdminList()
{
    search_form_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_ADMIN;

    QStringList headerList = { tr("Seq"), tr("Status"), tr("Type"), tr("Name"), tr("Email") };

    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<AdminRec> adminList;
    manApplet->dbMgr()->getAdminList( adminList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 80 );
    right_table_->setColumnWidth( 2, 80 );
    right_table_->setColumnWidth( 3, 160 );


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
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( admin.getEmail() )));
    }
}

void MainWindow::createRightConfigList( int nKind )
{
    search_form_->hide();
    removeAllRight();
    right_type_ = RightType::TYPE_CONFIG;

    QStringList headerList = { tr("Num"), tr("Kind"), tr("Name"), tr("Value") };

    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    QList<ConfigRec> configList;

    if( nKind >= 0 )
        manApplet->dbMgr()->getConfigList( nKind, configList );
    else
        manApplet->dbMgr()->getConfigList( configList );

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 100 );
    right_table_->setColumnWidth( 2, 180 );


    for( int i = 0; i < configList.size(); i++ )
    {
        ConfigRec config = configList.at(i);

        QTableWidgetItem *item = new QTableWidgetItem( config.getName() );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( config.getNum() ));
        QTableWidgetItem *kind = new QTableWidgetItem( QString("%1").arg( JS_GEN_getKindName( config.getKind() )));
        seq->setIcon(QIcon(":/images/config.png"));

        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, kind );
        right_table_->setItem(i,2, item);
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( config.getValue() )));
    }
}


void MainWindow::createRightAuditList()
{
    search_form_->show();

    int nTotalCount = 0;
//    int nLimit = kListCount;
    int nLimit = manApplet->settingsMgr()->listCount();
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Kind"), tr("Operation"), tr("UserName") };

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

    if( auditList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_AUDIT;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 140 );

    for( int i = 0; i < auditList.size(); i++ )
    {
        AuditRec audit = auditList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );
        QString strKind = JS_GEN_getKindName( audit.getKind() );
        QString strOperation = JS_GEN_getOperationName( audit.getOperation() );

        QTableWidgetItem *item = new QTableWidgetItem( strOperation );
        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( audit.getSeq() ));
        seq->setIcon(QIcon(":/images/audit.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( dateString( audit.getRegTime()) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( strKind )));
        right_table_->setItem(i,3, item );
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( audit.getUserName() )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

void MainWindow::createRightTSPList()
{
    search_form_->show();

    int nTotalCount = 0;
    int nLimit = manApplet->settingsMgr()->listCount();;
    int nPage = search_form_->curPage();
    int nOffset = nPage * nLimit;

    QString strTarget = search_form_->getCondName();
    QString strWord = search_form_->getInputWord();

    QStringList headerList = { tr("Seq"), tr("RegTime"), tr("Serial"), tr("SrcHash"), tr("Policy") };

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

    if( tspList.size() < 1 && strWord.length() > 0 )
    {
        manApplet->warningBox( tr( "There is no data" ), this );
        return;
    }

    right_type_ = RightType::TYPE_TSP;
    removeAllRight();
    right_table_->clear();

    right_table_->setColumnCount(headerList.size());
    right_table_->setHorizontalHeaderLabels(headerList);
    right_table_->verticalHeader()->setVisible(false);

    right_table_->setColumnWidth( 0, 60 );
    right_table_->setColumnWidth( 1, 130 );
    right_table_->setColumnWidth( 2, 100 );
    right_table_->setColumnWidth( 3, 80 );

    for( int i = 0; i < tspList.size(); i++ )
    {
        TSPRec tsp = tspList.at(i);
        right_table_->insertRow(i);
        right_table_->setRowHeight(i, 10 );

        QTableWidgetItem *seq = new QTableWidgetItem( QString("%1").arg( tsp.getSeq() ));
        seq->setIcon(QIcon(":/images/timestamp.png"));

        right_table_->setItem(i,0, seq );
        right_table_->setItem(i,1, new QTableWidgetItem(QString("%1").arg( dateString( tsp.getRegTime()) )));
        right_table_->setItem(i,2, new QTableWidgetItem(QString("%1").arg( tsp.getSerial())));
        right_table_->setItem(i,3, new QTableWidgetItem(QString("%1").arg( tsp.getSrcHash() )));
        right_table_->setItem(i,4, new QTableWidgetItem(QString("%1").arg( tsp.getPolicy() )));
    }

    search_form_->setTotalCount( nTotalCount );
    search_form_->updatePageLabel();
}

#ifdef _ENABLE_CHARTS
void MainWindow::createRightStatistics()
{
    printf( "Set Statistics\n" );
    //stack_->addWidget( statistics_ );
    stack_->setCurrentIndex(1);
}
#endif

void MainWindow::infoLine()
{
    info( "================================================================================\n" );
}

void MainWindow::infoLine2()
{
    info( "--------------------------------------------------------------------------------\n" );
}

void MainWindow::infoKeyPair(int seq)
{
    int nFieldWidth = -24;

    if( manApplet->dbMgr() == NULL ) return;
    KeyPairRec keyPair;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    manApplet->dbMgr()->getKeyPairRec( seq, keyPair );

    manApplet->mainWindow()->infoClear();

    infoLine();
    info( "== KeyPair Information\n" );
    infoLine();
    info( QString("Num        : %1\n").arg( keyPair.getNum() ));
    info( QString("Algorithm  : %1\n").arg(keyPair.getAlg()));
    info( QString("Name       : %1\n").arg(keyPair.getName()));
    info( QString("Param      : %1\n").arg(keyPair.getParam()));
    info( QString("Status     : %1 = %2\n").arg(getRecStatusName(keyPair.getStatus()), nFieldWidth ).arg(keyPair.getStatus()));

    info( QString("PublicKey\n") );
    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( keyPair.getPublicKey(), nWidth )));
    infoLine2();

    if( manApplet->settingsMgr()->showPriInfo() == true )
    {
        if( isInternalPrivate( keyPair.getAlg() ) == true )
        {
            info( QString("PrivateKey\n"));
            infoLine2();
            info( QString("%1\n").arg( getHexStringArea( keyPair.getPrivateKey(), nWidth )));
        }
        else
            info( QString("Private ID : %1\n").arg( getHexStringArea( keyPair.getPrivateKey(), nWidth )));
    }
    else
        info( QString("PrivateKey : [hidden]\n" ));


    infoLine();

    infoCursorTop();
}

void MainWindow::infoRequest( int seq )
{
    int nFieldWidth = -24;

    if( manApplet->dbMgr() == NULL ) return;
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    ReqRec reqRec;
    manApplet->dbMgr()->getReqRec( seq, reqRec );

    QString strKeyName = manApplet->dbMgr()->getNumName( reqRec.getKeyNum(), "TB_KEY_PAIR", "NAME" );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Request Information\n" );
    infoLine();
    info( QString("SEQ      : %1\n").arg(reqRec.getSeq()));
    info( QString("KeyNum   : %1 = %2\n").arg(reqRec.getKeyNum(), nFieldWidth).arg( strKeyName ));
    info( QString("Name     : %1\n").arg(reqRec.getName()));
    info( QString("DN       : %1\n").arg(reqRec.getDN()));
    info( QString("Hash     : %1\n").arg(reqRec.getHash()));
    info( QString("Status   : %1 = %2\n").arg( getRecStatusName(reqRec.getStatus()), nFieldWidth ).arg(reqRec.getStatus()));
    info( QString("Request\n") );
    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( reqRec.getCSR(), nWidth )));

    infoLine();

    infoCursorTop();
}

void MainWindow::infoCertificate( int seq )
{
    int nFieldWidth = -20;
    if( manApplet->dbMgr() == NULL ) return;

    char    sRegDate[64];

    CertRec certRec;
    manApplet->dbMgr()->getCertRec( seq, certRec );
    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

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
    {
        if( certRec.getIssuerNum() == kSelfNum )
            strIssuerName = "SelfSign";
        else if( certRec.getIssuerNum() == kImportNum )
            strIssuerName = "Import (Unknown)";
        else
            strIssuerName = "Unknown";
    }


    if( certRec.getUserNum() > 0 )
        strUserName = manApplet->dbMgr()->getNumName( certRec.getUserNum(), "TB_USER", "NAME" );
    else
        strUserName = "Unknown";

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Certificate Information\n" );
    infoLine();
    info( QString("Num           : %1\n").arg(certRec.getNum()));
    JS_UTIL_getDateTime( certRec.getRegTime(), sRegDate );
    info( QString("RegDate       : %1\n").arg(sRegDate));
    info( QString("KeyNum        : %1 = %2\n").arg( strKeyName, nFieldWidth ).arg(certRec.getKeyNum()));

    if( manApplet->isPRO() )
        info( QString("UserNum       : %1 | %2\n").arg( strUserName, nFieldWidth ).arg(certRec.getUserNum()));

    info( QString("SignAlgorithm : %1\n").arg(certRec.getSignAlg()));
    info( QString("IsCA          : %1 = %2\n").arg( certRec.isCA() ? "Yes" : "No", nFieldWidth ).arg(certRec.isCA()));
    info( QString("IsSelf        : %1 = %2\n").arg( certRec.isSelf() ? "Yes" : "No", nFieldWidth ).arg(certRec.isSelf()));
    info( QString("SubjectDN     : %1\n").arg(certRec.getSubjectDN()));
    info( QString("IssuerNum     : %1 = %2\n").arg( strIssuerName, nFieldWidth).arg(certRec.getIssuerNum()));
    info( QString("Status        : %1 = %2\n").arg( getCertStatusName( certRec.getStatus() ), nFieldWidth).arg(certRec.getStatus()));
    info( QString("Serial        : %1\n").arg(certRec.getSerial()));
    info( QString("DNHash        : %1\n").arg(certRec.getDNHash()));
    info( QString("KeyHash       : %1\n").arg(certRec.getKeyHash()));
    info( QString("CRLDP         : %1\n").arg(certRec.getCRLDP()));

    info( QString("Certificate\n") );
    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( certRec.getCert(), nWidth )));

    infoLine();

    infoCursorTop();
}

void MainWindow::infoCertProfile( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    CertProfileRec certProfile;

    manApplet->dbMgr()->getCertProfileRec( seq, certProfile );

    QString strVersion;
    QString strNotBefore;
    QString strNotAfter;
    QString strDNTemplate;

    strVersion = QString( "V%1" ).arg( certProfile.getVersion() + 1);

    if( certProfile.getNotBefore() == kPeriodDay )
    {
        strNotBefore = QString("CreationTime");
        strNotAfter = QString( "%1 Days" ).arg( certProfile.getNotAfter() );
    }
    else if( certProfile.getNotBefore() == kPeriodMonth )
    {
        strNotBefore = QString("CreationTime");
        strNotAfter = QString( "%1 Months" ).arg( certProfile.getNotAfter() );
    }
    else if( certProfile.getNotBefore() == kPeriodYear )
    {
        strNotBefore = QString("CreationTime");
        strNotAfter = QString( "%1 Years" ).arg( certProfile.getNotAfter() );
    }
    else
    {
        strNotBefore = getDateTime( certProfile.getNotBefore() );
        strNotAfter = getDateTime( certProfile.getNotAfter() );
    }

    if( certProfile.getDNTemplate() == kCSR_DN )
        strDNTemplate = "Use CSR DN";
    else
        strDNTemplate = certProfile.getDNTemplate();

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Certificate Profile Information\n" );
    infoLine();
    info( QString("Num         : %1\n").arg(certProfile.getNum()));
    info( QString("Name        : %1\n").arg(certProfile.getName()));
    info( QString("Type        : %1 = %2\n").arg( getProfileType( certProfile.getType()), nFieldWidth).arg(certProfile.getType()));
    info( QString("Version     : %1 = %2\n").arg( strVersion, nFieldWidth ).arg(certProfile.getVersion()));

    if( certProfile.getType() == JS_PKI_PROFILE_TYPE_CERT )
    {
        info( QString("NotBefore   : %1 = %2\n").arg( strNotBefore, nFieldWidth).arg(certProfile.getNotBefore()));
        info( QString("NotAfter    : %1 = %2\n").arg( strNotAfter, nFieldWidth).arg(certProfile.getNotAfter()));
        info( QString("ExtUsage    : %1 = %2\n").arg(getExtUsage(certProfile.getExtUsage()), nFieldWidth).arg(certProfile.getExtUsage()));
        info( QString("DNTemplate  : %1 = %2\n").arg(strDNTemplate, nFieldWidth).arg(certProfile.getDNTemplate()));
    }

    info( QString("Hash        : %1\n").arg(certProfile.getHash()));
    infoLine();

    QList<ProfileExtRec> extList;
    manApplet->dbMgr()->getCertProfileExtensionList( seq, extList );

    if( extList.size() > 0 )
        info( QString( "== Extensions Informations [ Count: %1 ]\n" ).arg( extList.size() ) );

    for( int i = 0; i < extList.size(); i++ )
    {
        ProfileExtRec extRec = extList.at(i);
        infoProfileExt( extRec );
    }

    infoCursorTop();
}

void MainWindow::infoProfileExt( ProfileExtRec& profileExt )
{
    QString strSN = profileExt.getSN();
    QString strValue = profileExt.getValue();
    QString strShowValue = getProfileExtInfoValue( strSN, strValue );

    infoLine();
    info( QString( "| %1 | %2 | Seq: %3 |\n")
                     .arg( profileExt.getSN(), -45 )
                     .arg( profileExt.isCritical() ? "Critical" : "Normal", -10 )
                     .arg( profileExt.getSeq(), 10 ));

    if( strShowValue.length() > 0 )
    {
        infoLine2();
        info( QString( "%1" ).arg( strShowValue ) );
    }

    infoLine();
}

void MainWindow::infoCRL( int seq )
{
    int nFieldWidth = -24;

    if( manApplet->dbMgr() == NULL ) return;

    CRLRec crlRec;
    char    sRegTime[64];
    char    sThisUpdate[64];
    char    sNextUpdate[64];

    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    manApplet->dbMgr()->getCRLRec( seq, crlRec );
    QString strIssuerName;

    if( crlRec.getIssuerNum() > 0 )
        strIssuerName = manApplet->dbMgr()->getNumName( crlRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
    else if( crlRec.getIssuerNum() == kImportNum )
        strIssuerName = "Import (Unknown)";
    else
        strIssuerName = "Unknown";

    JS_UTIL_getDateTime( crlRec.getRegTime(), sRegTime );
    JS_UTIL_getDateTime( crlRec.getThisUpdate(), sThisUpdate );
    JS_UTIL_getDateTime( crlRec.getNextUpdate(), sNextUpdate );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== CRL Information\n" );
    infoLine();
    info( QString("Num             : %1\n").arg(crlRec.getNum()));
    info( QString("RegTime         : %1\n").arg(sRegTime));
    info( QString("IssuerNum       : %1 = %2\n").arg( strIssuerName, nFieldWidth ).arg(crlRec.getIssuerNum()));
    info( QString("SignAlgorithm   : %1\n").arg(crlRec.getSignAlg()));
    info( QString("ThisUpdate      : %1\n").arg(sThisUpdate));
    info( QString("NextUpdate      : %1\n").arg(sNextUpdate));
    info( QString("CRLDP           : %1\n").arg( crlRec.getCRLDP() ));
    info( QString("CRL\n"));
    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( crlRec.getCRL(), nWidth )));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoCRLProfile( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    CRLProfileRec crlProfile;

    manApplet->dbMgr()->getCRLProfileRec( seq, crlProfile );

    QString strVersion;
    QString strThisUpdate;
    QString strNextUpdate;

    strVersion = QString( "V%1" ).arg( crlProfile.getVersion() + 1);

    if( crlProfile.getThisUpdate() == kPeriodDay )
    {
        strThisUpdate = QString("CreationTime");
        strNextUpdate = QString( "%1 Days" ).arg( crlProfile.getNextUpdate() );
    }
    else if( crlProfile.getThisUpdate() == kPeriodMonth )
    {
        strThisUpdate = QString("CreationTime");
        strNextUpdate = QString( "%1 Months" ).arg( crlProfile.getNextUpdate() );
    }
    else if( crlProfile.getThisUpdate() == kPeriodYear )
    {
        strThisUpdate = QString("CreationTime");
        strNextUpdate = QString( "%1 Years" ).arg( crlProfile.getNextUpdate() );
    }
    else
    {
        strThisUpdate = getDateTime( crlProfile.getThisUpdate() );
        strNextUpdate = getDateTime( crlProfile.getNextUpdate() );
    }

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== CRL Profile Information\n" );
    infoLine();
    info( QString("Num          : %1\n").arg(crlProfile.getNum()));
    info( QString("Name         : %1\n").arg(crlProfile.getName()));
    info( QString("Version      : %1 = %2\n").arg(strVersion, nFieldWidth).arg(crlProfile.getVersion()));
    info( QString("ThisUpdate   : %1 = %2\n").arg(strThisUpdate, nFieldWidth).arg(crlProfile.getThisUpdate()));
    info( QString("NextUpdate   : %1 = %2\n").arg(strNextUpdate, nFieldWidth).arg(crlProfile.getNextUpdate()));
    info( QString("Hash         : %1\n").arg(crlProfile.getHash()));
    infoLine();

    QList<ProfileExtRec> extList;
    manApplet->dbMgr()->getCRLProfileExtensionList( seq, extList );

    if( extList.size() > 0 )
        info( QString( "== Extensions Informations [ Count: %1 ]\n" ).arg( extList.size() ) );

    for( int i = 0; i < extList.size(); i++ )
    {
        ProfileExtRec extRec = extList.at(i);
        infoProfileExt( extRec );
    }

    infoCursorTop();
}

void MainWindow::infoRevoke( int seq )
{
    int nFieldWidth = -20;
    if( manApplet->dbMgr() == NULL ) return;

    RevokeRec revokeRec;
    manApplet->dbMgr()->getRevokeRec( seq, revokeRec );

    QString strCertName = manApplet->dbMgr()->getNumName( revokeRec.getCertNum(), "TB_CERT", "SUBJECTDN" );
    QString strIsserName = manApplet->dbMgr()->getNumName( revokeRec.getIssuerNum(), "TB_CERT", "SUBJECTDN" );
    QString strReason = JS_PKI_getRevokeReasonName( revokeRec.getReason() );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Revoke Information\n" );
    infoLine();
    info( QString("Seq          : %1\n").arg( revokeRec.getSeq()));
    info( QString("CertNum      : %1 = %2\n").arg(strCertName, nFieldWidth).arg( revokeRec.getCertNum()));
    info( QString("IssuerNum    : %1 = %2\n").arg(strIsserName, nFieldWidth).arg( revokeRec.getIssuerNum()));
    info( QString("Serial       : %1\n").arg( revokeRec.getSerial()));
    info( QString("RevokeDate   : %1\n").arg( getDateTime( revokeRec.getRevokeDate() )));
    info( QString("Reason       : %1 = %2\n").arg(strReason, nFieldWidth).arg( revokeRec.getReason()));
    info( QString("CRLDP        : %1\n").arg( revokeRec.getCRLDP()));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoUser( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    UserRec userRec;
    manApplet->dbMgr()->getUserRec( seq, userRec );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== User Information\n" );
    infoLine();
    info( QString("Num           : %1\n").arg(userRec.getNum()));
    info( QString("RegTime       : %1\n").arg(getDateTime(userRec.getRegTime())));
    info( QString("Name          : %1\n").arg(userRec.getName()));
    info( QString("SSN           : %1\n").arg(userRec.getSSN()));
    info( QString("Email         : %1\n").arg(userRec.getEmail()));
    info( QString("Status        : %1 = %2\n").arg(getUserStatusName(userRec.getStatus()), nFieldWidth).arg(userRec.getStatus()) );
    info( QString("RefNum        : %1\n").arg(userRec.getRefNum()));
    info( QString("AuthCode      : %1\n").arg(userRec.getAuthCode()));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoAdmin( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    AdminRec adminRec;
    manApplet->dbMgr()->getAdminRec( seq, adminRec );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Admin Information\n" );
    infoLine();
    info( QString("Seq          : %1\n").arg(adminRec.getSeq()));
    info( QString("Status       : %1 = %2\n").arg(getStatusName(adminRec.getStatus()), nFieldWidth).arg(adminRec.getStatus()));
    info( QString("Type         : %1 = %2\n").arg(getAdminTypeName(adminRec.getType()), nFieldWidth ).arg(adminRec.getType()));
    info( QString("Name         : %1\n").arg(adminRec.getName()));
    info( QString("Password     : %1\n").arg(adminRec.getPassword()));
    info( QString("Email        : %1\n").arg(adminRec.getEmail()));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoConfig( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    ConfigRec configRec;
    manApplet->dbMgr()->getConfigRec( seq, configRec );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Config Information\n" );
    infoLine();
    info( QString("Num          : %1\n").arg(configRec.getNum()));
    info( QString("Kind         : %1 = %2\n").arg( JS_GEN_getKindName( configRec.getKind()), nFieldWidth).arg(configRec.getKind()));
    info( QString("Name         : %1\n").arg(configRec.getName()));
    info( QString("Value        : %1\n").arg(configRec.getValue()));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoKMS( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    KMSRec kmsRec;
    manApplet->dbMgr()->getKMSRec( seq, kmsRec );

    QString strType = JS_KMS_getObjectTypeName( kmsRec.getType() );
    QString strAlgorithm = JS_PKI_getKeyAlgName( kmsRec.getAlgorithm() );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== KMS Information\n" );
    infoLine();
    info( QString("Seq         : %1\n").arg(kmsRec.getSeq()));
    info( QString("RegTime     : %1\n").arg(getDateTime(kmsRec.getRegTime())));
    info( QString("State       : %1 = %2\n").arg(kmsRec.getState(), nFieldWidth).arg( getStatusName(kmsRec.getState())));
    info( QString("Type        : %1 = %2\n").arg(kmsRec.getType(), nFieldWidth).arg(strType));
    info( QString("Algorithm   : %1 = %2\n").arg(kmsRec.getAlgorithm(), nFieldWidth).arg( strAlgorithm ));
    info( QString("ID          : %1\n").arg(kmsRec.getID()));
    info( QString("Info        : %1\n").arg(kmsRec.getInfo()));
    info( "============================ Attribute =================================\n" );

    QList<KMSAttribRec> kmsAttribList;
    manApplet->dbMgr()->getKMSAttribList( seq, kmsAttribList );

    for( int i = 0; i < kmsAttribList.size(); i++ )
    {
        KMSAttribRec attribRec = kmsAttribList.at(i);

        info( QString( "%1 || %2 || %3\n")
                .arg(attribRec.getNum())
                .arg(JS_KMS_attributeName(attribRec.getType()))
                .arg(attribRec.getValue()));
    }

    infoCursorTop();
}

void MainWindow::infoAudit( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    AuditRec auditRec;
    manApplet->dbMgr()->getAuditRec( seq, auditRec );

    QString strKind = JS_GEN_getKindName( auditRec.getKind() );
    QString strOperation = JS_GEN_getOperationName( auditRec.getOperation() );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Audit Information\n" );
    infoLine();
    info( QString("Seq          : %1\n").arg(auditRec.getSeq()));
    info( QString("Kind         : %1 = %2\n").arg(strKind, nFieldWidth).arg(auditRec.getKind()));
    info( QString("Operation    : %1 = %2\n").arg(strOperation, nFieldWidth).arg(auditRec.getOperation()));
    info( QString("UserName     : %1\n").arg(auditRec.getUserName()));
    info( QString("Info         : %1\n").arg(auditRec.getInfo()));
    info( QString("MAC          : %1\n").arg(auditRec.getMAC()));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoTSP( int seq )
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    int nWidth = manApplet->settingsMgr()->hexAreaWidth();

    TSPRec tspRec;
    manApplet->dbMgr()->getTSPRec( seq, tspRec );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== TSP Information\n" );
    infoLine();
    info( QString("Seq          : %1\n").arg(tspRec.getSeq()));
    info( QString("RegTime      : %1\n").arg(getDateTime(tspRec.getRegTime())));
    info( QString("Serial       : %1\n").arg(tspRec.getSerial()));
    info( QString("Policy       : %1\n").arg(tspRec.getPolicy()));
    info( QString("TSTInfo\n"));
    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( tspRec.getTSTInfo(), nWidth )));
    infoLine2();
    info( QString("Data\n"));
    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( tspRec.getData(), nWidth )));
    infoLine();

    infoCursorTop();
}

void MainWindow::infoSigner(int seq)
{
    int nFieldWidth = -24;
    if( manApplet->dbMgr() == NULL ) return;

    int nWidth = manApplet->settingsMgr()->hexAreaWidth();
    SignerRec signerRec;
    manApplet->dbMgr()->getSignerRec( seq, signerRec );

    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Signer Information\n" );
    infoLine();
    info( QString("Num          : %1\n").arg( signerRec.getNum()));
    info( QString("RegTime      : %1\n").arg(getDateTime(signerRec.getRegTime())));
    info( QString("Type         : %1 = %2\n").arg(getSignerTypeName(signerRec.getType()), nFieldWidth).arg(signerRec.getType()));
    info( QString("DN           : %1\n").arg(signerRec.getDN()));
    info( QString("DNHash       : %1\n").arg(signerRec.getDNHash()));
    info( QString("Status       : %1 = %2\n").arg(getStatusName(signerRec.getType()), nFieldWidth).arg(signerRec.getStatus()));
    info( QString("Info         : %1\n").arg(signerRec.getInfo()));
    info( QString("Certificate\n") );

    infoLine2();
    info( QString("%1\n").arg( getHexStringArea( signerRec.getCert(), nWidth ) ));

    infoLine();

    infoCursorTop();
}

void MainWindow::infoStatistics()
{
    manApplet->mainWindow()->infoClear();
    infoLine();
    info( "== Statistics Information\n" );
    infoLine();

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
