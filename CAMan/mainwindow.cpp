#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "man_tree_item.h"
#include "man_tree_model.h"
#include "man_tree_view.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    initialize();
}

MainWindow::~MainWindow()
{
    delete hsplitter_;
    delete vsplitter_;
    delete leftTree_;
    delete leftModel_;
    delete rightText_;
    delete rightTable_;
}


void MainWindow::initialize()
{
    hsplitter_ = new QSplitter(Qt::Horizontal);
    vsplitter_ = new QSplitter(Qt::Vertical);
    leftTree_ = new ManTreeView(this);
    rightText_ = new QTextEdit();
    rightTable_ = new QTableWidget;
    leftModel_ = new ManTreeModel(this);

    leftTree_->setModel(leftModel_);

    hsplitter_->addWidget(leftTree_);
    hsplitter_->addWidget(vsplitter_);
    vsplitter_->addWidget(rightTable_);
    vsplitter_->addWidget(rightText_);

    QList <int> vsizes;
    vsizes << 1200 << 500;
    vsplitter_->setSizes(vsizes);

    QList <int> sizes;
    sizes << 500 << 1200;
    resize(1024,768);

    hsplitter_->setSizes(sizes);
    setCentralWidget(hsplitter_);
}
