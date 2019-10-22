#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "man_tree_item.h"
#include "man_tree_model.h"
#include "man_tree_view.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    db_ = NULL;

    initialize();

    createActions();
    createStatusBar();

    setUnifiedTitleAndToolBarOnMac(true);
    setAcceptDrops(true);
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


void MainWindow::newFile()
{

}

void MainWindow::open()
{

}

void MainWindow::quit()
{
    QCoreApplication::exit();
}


void MainWindow::newKey()
{

}

void MainWindow::makeRequest()
{

}

void MainWindow::makeCertPolicy()
{

}

void MainWindow::makeCRLPolicy()
{

}

void MainWindow::makeCertificate()
{

}

void MainWindow::makeCRL()
{

}

void MainWindow::revokeCertificate()
{

}

void MainWindow::importPrivateKey()
{

}

void MainWindow::importEncPrivateKey()
{

}

void MainWindow::importRequest()
{

}

void MainWindow::importCertificate()
{

}

void MainWindow::importCRL()
{

}

void MainWindow::importPFX()
{

}

void MainWindow::exportPrivateKey()
{

}

void MainWindow::exportEncPrivateKey()
{

}

void MainWindow::exportRequest()
{

}

void MainWindow::exportCertificate()
{

}

void MainWindow::exportCRL()
{

}

void MainWindow::exportPFX()
{

}

void MainWindow::publishLDAP()
{

}

void MainWindow::getLDAP()
{

}

void MainWindow::about()
{

}

void MainWindow::settings()
{

}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}
