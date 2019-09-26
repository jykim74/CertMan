#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextEdit>

class ManTreeView;
class ManTreeModel;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void initialize();

private:
//    Ui::MainWindow *ui;
    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *leftTree_;
    ManTreeModel    *leftModel_;
    QTableWidget    *rightTable_;
    QTextEdit       *rightText_;
};

#endif // MAINWINDOW_H
