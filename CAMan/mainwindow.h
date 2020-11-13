#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextEdit>
#include <QtSql>
#include <QStackedLayout>



class ManTreeView;
class ManTreeModel;
class ManTreeItem;
class SearchMenu;
class CertRec;
class DBMgr;
class StatForm;

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
    TYPE_REVOKE,
    TYPE_USER,
    TYPE_ADMIN,
    TYPE_SIGNER,
    TYPE_KMS,
    TYPE_STATISTICS,
    TYPE_AUDIT,
    TYPE_TSP
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    ManTreeItem* currentItem();

    void initialize();
    void showWindow();
    void createActions();
    void createStatusBar();
    void createTableMenu();

    void createTreeMenu();
    void createRightList( int nType, int nNum );
    void createRightKeyPairList();
    void createRightRequestList();
    void createRightCertPolicyList();
    void createRightCRLPolicyList();
    void createRightCertList( int nIssuerNum, bool bIsCA = false );
    void createRightCRLList(int nIssuerNum);
    void createRightRevokeList( int nIssuerNum );
    void createRightAdminList();
    void createRightUserList();
    void createRightKMSList();
    void createRightSignerList(int nType);
    void createRightStatistics();
    void createRightAuditList();
    void createRightTSPList();

    void removeAllRight();

    void showRightKeyPair( int seq );
    void showRightRequest( int seq );
    void showRightCertificate( int seq );
    void showRightCertPolicy( int seq );
    void showRightCRL( int seq );
    void showRightCRLPolicy( int seq );
    void showRightRevoke( int seq );
    void showRightUser( int seq );
    void showRightAdmin( int seq );
    void showRightKMS( int seq );
    void showRightAudit( int seq );
    void showRightTSP( int seq );
    void showRightSigner( int seq );
    void showRightStatistics();

    int rightType() { return right_type_; };
    int rightCount();

    DBMgr* dbMgr() { return db_mgr_; };



public slots:
    void newFile();
    void open();
    void openRecent();
    void quit();

    void newKey();
    void makeRequest();
    void makeCertPolicy();
    void makeCRLPolicy();
    void editCertPolicy();
    void editCRLPolicy();
    void makeCertificate();
    void makeCRL();
    void revokeCertificate();
    void registerUser();
    void registerREGSigner();
    void registerOCSPSigner();

    void viewCertificate();
    void viewCRL();

    void importData();
    void importCert();
    void importCRL();
    void exportPriKey();
    void exportEncPriKey();
    void exportPubKey();
    void exportRequest();
    void exportCertificate();
    void exportCRL();
    void exportPFX();

    void deleteCertPolicy();
    void deleteCRLPolicy();
    void deleteCertificate();
    void deleteCRL();
    void deleteKeyPair();
    void deleteRequest();

    void deleteUser();
    void deleteSigner();

    void registerAdmin();
    void editAdmin();

    void publishLDAP();
    void getLDAP();
    void expandMenu();
    void expandItem( ManTreeItem *item );
    void addRootCA( CertRec& certRec );
    void checkCertificate();
    void certStatus();
    void checkOCSP();
    void tsp();
    void statusByReg();
    void revokeByReg();

    void about();
    void settings();
    void serverStatus();

    void treeMenuClick( QModelIndex index );
    void treeMenuDoubleClick( QModelIndex index );
    void tableClick( QModelIndex index );

    void activateKey();
    void registerKey();
    void deleteKey();

    void issueCMP();
    void updateCMP();
    void revokeCMP();

    void verifyAudit();
    void viewTSTInfo();
    void verifyTSMessage();

    void issueSCEP();
    void renewSCEP();
    void getCRLSCEP();

private slots:
    void showRightMenu( QPoint point );

    virtual void dragEnterEvent( QDragEnterEvent *event );
    virtual void dropEvent( QDropEvent *event );

private:
    void setTitle( const QString strName );
    void setPath( const QString strFilePath );

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();


    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTextEdit       *right_text_;
    SearchMenu      *search_menu_;

    DBMgr           *db_mgr_;
    int             right_type_;
    ManTreeItem     *root_ca_;
    QStackedLayout  *stack_;

    StatForm        *stat_;

    int             openDB( const QString dbPath );
};

#endif // MAINWINDOW_H
