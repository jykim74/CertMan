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
}

void MainWindow::createStatusBar()
{
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::newFile()
{

}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}
