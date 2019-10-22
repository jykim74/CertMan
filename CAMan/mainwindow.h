#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextEdit>
#include <QtSql>

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
    void showWindow();
    void createActions();
    void createStatusBar();

    QSqlDatabase* getDB() {return db_;};

private slots:
    void newFile();

private:
//    Ui::MainWindow *ui;
    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTextEdit       *right_text_;

    QSqlDatabase    *db_;
};

#endif // MAINWINDOW_H
