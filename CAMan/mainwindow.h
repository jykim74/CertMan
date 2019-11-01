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
class DBMgr;

namespace Ui {
class MainWindow;
}

enum RightType {
    TYPE_KEYPAIR = 1,
    TYPE_REQUEST,
    TYPE_CERTIFICATE,
    TYPE_CERT_POLICY,
    TYPE_CRL_POLICY,
    TYPE_CRL,
    TYPE_REVOKE
};

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
    void createTableMenu();

    void createTreeMenu();
    void createRightKeyPairList();
    void createRightRequestList();
    void createRightCertPolicyList();
    void createRightCRLPolicyList();
    void createRightCertList( int nIssuerNum );
    void createRightCRLList(int nIssuerNum);

    void removeAllRight();

    void showRightKeyPair( int seq );
    void showRightRequest( int seq );
    void showRightCertificate( int seq );
    void showRightCertPolicy( int seq );
    void showRightCRL( int seq );
    void showRightCRLPolicy( int seq );
    void showRightRevoke( int seq );

    DBMgr* dbMgr() { return db_mgr_; };



public slots:
    void newFile();
    void open();
    void quit();

    void newKey();
    void makeRequest();
    void makeCertPolicy();
    void makeCRLPolicy();
    void makeCertificate();
    void makeCRL();
    void revokeCertificate();

    void importPrivateKey();
    void importEncPrivateKey();
    void importRequest();
    void importCertificate();
    void importCRL();
    void importPFX();

    void exportPrivateKey();
    void exportEncPrivateKey();
    void exportRequest();
    void exportCertificate();
    void exportCRL();
    void exportPFX();

    void publishLDAP();
    void getLDAP();

    void about();
    void settings();

    void menuClick( QModelIndex index );
    void tableClick( QModelIndex index );

private slots:
    void showRightMenu( QPoint point );

private:
//    Ui::MainWindow *ui;
    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTextEdit       *right_text_;

    DBMgr           *db_mgr_;
    int             right_type_;
};

#endif // MAINWINDOW_H
