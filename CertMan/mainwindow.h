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
class StatForm;

namespace Ui {
class MainWindow;
}

enum RightType {
    TYPE_KEYPAIR = 1,
    TYPE_REQUEST,
    TYPE_CERTIFICATE,
    TYPE_CERT_PROFILE,
    TYPE_CRL_PROFILE,
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
    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void logClear();
    void logCurorTop();

    void createActions();
    void createStatusBar();
    void createTableMenu();

    void createTreeMenu();
    void createRightList( int nType, int nNum );
    void createRightKeyPairList();
    void createRightRequestList();
    void createRightCertProfileList();
    void createRightCRLProfileList();
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

    void logKeyPair( int seq );
    void logRequest( int seq );
    void logCertificate( int seq );
    void logCertProfile( int seq );
    void logCRL( int seq );
    void logCRLProfile( int seq );
    void logRevoke( int seq );
    void logUser( int seq );
    void logAdmin( int seq );
    void logKMS( int seq );
    void logAudit( int seq );
    void logTSP( int seq );
    void logSigner( int seq );
    void logStatistics();

    int rightType() { return right_type_; };
    int rightCount();

public slots:
    void newFile();
    void open();
    void openRecent();
    void quit();

    void newKey();
    void makeRequest();
    void makeCertProfile();
    void makeCRLProfile();
    void editCertProfile();
    void editCRLProfile();
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

    void deleteCertProfile();
    void deleteCRLProfile();
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
    QTextEdit       *log_text_;
    SearchMenu      *search_menu_;

    int             right_type_;
    ManTreeItem     *root_ca_;
    QStackedLayout  *stack_;

    StatForm        *stat_;

    int             openDB( const QString dbPath );
};

#endif // MAINWINDOW_H
