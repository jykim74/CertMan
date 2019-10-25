#include <QFileDialog>

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

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    db_mgr_ = new DBMgr;

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

    connect( left_tree_, SIGNAL(clicked(QModelIndex)), this, SLOT(menuClick(QModelIndex)));
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
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("QFileDialog::getOpenFileName()"),
                                                     "./",
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
}

void MainWindow::createRightKeyPairList()
{
    QStringList headerList = { "Number", "Algorithm", "Name", "PublicKey", "PrivateKey", "Status" };

    right_table_->setHorizontalHeaderLabels( headerList );

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
        right_table_->setItem(i, 5, new QTableWidgetItem( QString("%1").arg(keyPairRec.getStatus())));
    }
}


void MainWindow::createRightRequestList()
{
    right_table_->clear();

    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("SEQ") ));
    right_table_->setHorizontalHeaderItem( 1, new QTableWidgetItem(QString("KEY_NUM") ));
    right_table_->setHorizontalHeaderItem( 2, new QTableWidgetItem(QString("NAME") ));
    right_table_->setHorizontalHeaderItem( 3, new QTableWidgetItem(QString("DN") ));
    right_table_->setHorizontalHeaderItem( 4, new QTableWidgetItem(QString("CSR") ));
    right_table_->setHorizontalHeaderItem( 5, new QTableWidgetItem(QString("HASH") ));
    right_table_->setHorizontalHeaderItem( 6, new QTableWidgetItem(QString("STATUS") ));

    QList<ReqRec> reqList;
    db_mgr_->getReqList( reqList );

    for( int i=0; i < reqList.size(); i++ )
    {
        ReqRec reqRec = reqList.at(i);

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
    right_table_->clear();

    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("NUM")));
    right_table_->setHorizontalHeaderItem( 1, new QTableWidgetItem(QString("NAME")));
    right_table_->setHorizontalHeaderItem( 2, new QTableWidgetItem(QString("VERSION")));
    right_table_->setHorizontalHeaderItem( 3, new QTableWidgetItem(QString("NOTBEFORE")));
    right_table_->setHorizontalHeaderItem( 4, new QTableWidgetItem(QString("NOTAFTER")));
    right_table_->setHorizontalHeaderItem( 5, new QTableWidgetItem(QString("HASH")));
    right_table_->setHorizontalHeaderItem( 6, new QTableWidgetItem(QString("DNTEMPLATE")));

    QList<CertPolicyRec> certPolicyList;
    db_mgr_->getCertPolicyList( certPolicyList );

    for( int i=0; i < certPolicyList.size(); i++ )
    {
        CertPolicyRec certPolicy = certPolicyList.at(i);

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
    right_table_->clear();

    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("NUM")));
    right_table_->setHorizontalHeaderItem( 1, new QTableWidgetItem(QString("NAME")));
    right_table_->setHorizontalHeaderItem( 2, new QTableWidgetItem(QString("VERSION")));
    right_table_->setHorizontalHeaderItem( 3, new QTableWidgetItem(QString("THISUPDATE")));
    right_table_->setHorizontalHeaderItem( 4, new QTableWidgetItem(QString("NEXTUPDATE")));
    right_table_->setHorizontalHeaderItem( 5, new QTableWidgetItem(QString("HASH")));

    QList<CRLPolicyRec> crlPolicyList;
    db_mgr_->getCRLPolicyList( crlPolicyList );

    for( int i=0; i < crlPolicyList.size(); i++ )
    {
        CRLPolicyRec crlPolicy = crlPolicyList.at(i);

        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crlPolicy.getNum() )) );
        right_table_->setItem( i, 1, new QTableWidgetItem( crlPolicy.getName()) );
        right_table_->setItem( i, 2, new QTableWidgetItem( QString("%1").arg(crlPolicy.getVersion() )) );
        right_table_->setItem( i, 3, new QTableWidgetItem( QString("%1").arg(crlPolicy.getThisUpdate())) );
        right_table_->setItem( i, 4, new QTableWidgetItem( QString("%1").arg(crlPolicy.getNextUpdate())) );
        right_table_->setItem( i, 5, new QTableWidgetItem( crlPolicy.getHash()) );
    }
}

void MainWindow::createCertList( int nIssuerNum )
{
    right_table_->clear();

    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("NUM") ));
    right_table_->setHorizontalHeaderItem( 1, new QTableWidgetItem(QString("KEYNUM") ));
    right_table_->setHorizontalHeaderItem( 2, new QTableWidgetItem(QString("SIGNALG") ));
    right_table_->setHorizontalHeaderItem( 3, new QTableWidgetItem(QString("CERT") ));
    right_table_->setHorizontalHeaderItem( 4, new QTableWidgetItem(QString("ISSELF") ));
    right_table_->setHorizontalHeaderItem( 5, new QTableWidgetItem(QString("ISCA") ));
    right_table_->setHorizontalHeaderItem( 6, new QTableWidgetItem(QString("ISSUERNUM") ));
    right_table_->setHorizontalHeaderItem( 7, new QTableWidgetItem(QString("SUBJECTDN") ));
    right_table_->setHorizontalHeaderItem( 8, new QTableWidgetItem(QString("STATUS") ));

    QList<CertRec> certList;
    db_mgr_->getCertList( nIssuerNum, certList );

    for( int i=0; i < certList.size(); i++ )
    {
        CertRec cert = certList.at(i);

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

void MainWindow::createCRLList( int nIssuerNum )
{
    right_table_->clear();

    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("NUM")));
    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("ISSUERNUM")));
    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("SIGNALG")));
    right_table_->setHorizontalHeaderItem( 0, new QTableWidgetItem(QString("CRL")));

    QList<CRLRec> crlList;
    db_mgr_->getCRLList( nIssuerNum, crlList );

    for( int i=0; i < crlList.size(); i++ )
    {
        CRLRec crl = crlList.at(i);

        right_table_->setItem( i, 0, new QTableWidgetItem( QString("%1").arg(crl.getNum() )));
        right_table_->setItem( i, 1, new QTableWidgetItem(QString("%1").arg(crl.getIssuerNum() )));
        right_table_->setItem( i, 2, new QTableWidgetItem( crl.getSignAlg() ));
        right_table_->setItem( i, 3, new QTableWidgetItem( crl.getCRL() ));
    }
}
