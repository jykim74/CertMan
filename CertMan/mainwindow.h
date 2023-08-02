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
    TYPE_CONFIG,
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
    ManTreeItem* currentTreeItem();

    void initialize();
    void showWindow();
    void setTitle( const QString strName );

    void logView( bool bShow = true );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void infoClear();
    void infoCursorTop();

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
    void createRightConfigList();
    void createRightUserList();
    void createRightKMSList();
    void createRightSignerList(int nType);
    void createRightStatistics();
    void createRightAuditList();
    void createRightTSPList();

    void removeAllRight();

    void infoKeyPair( int seq );
    void infoRequest( int seq );
    void infoCertificate( int seq );
    void infoCertProfile( int seq );
    void infoCRL( int seq );
    void infoCRLProfile( int seq );
    void infoRevoke( int seq );
    void infoUser( int seq );
    void infoAdmin( int seq );
    void infoConfig( int seq );
    void infoKMS( int seq );
    void infoAudit( int seq );
    void infoTSP( int seq );
    void infoSigner( int seq );
    void infoStatistics();

    int rightType() { return right_type_; };
    int rightCount();

    void loadDB( const QString& filename );

public slots:
    void newFile();
    void open();
    void remoteDB();
    void openRecent();
    void logout();
    void quit();

    void newKey();
    void makeRequest();
    void makeRequestSetKeyName();
    void makeCertProfile();
    void makeCRLProfile();
    void editCertProfile();
    void copyCertProfile();
    void editCRLProfile();
    void copyCRLProfile();
    void makeCertificate();
    void makeCRL();
    void renewCert();
    void revokeCertificate();


    void registerUser();
    void registerREGSigner();
    void registerOCSPSigner();
    void makeConfig();
    void editConfig();
    void deleteConfig();

    void viewCertificate();
    void viewCRL();
    void verifyCRL();
    void viewPriKey();
    void viewCSR();

    void importData();
    void importCert();
    void importCRL();
    void importCSR();
    void exportPriKey();
    void exportEncPriKey();
    void exportPubKey();
    void exportRequest();
    void exportCertificate();
    void exportCRL();
    void exportPFX();
    void setPasswd();

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

#ifdef USE_OCSP
    void checkOCSP();
#endif
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

#ifdef USE_CMP
    void issueCMP();
    void updateCMP();
    void revokeCMP();
#endif

    void verifyAudit();
    void viewTSTInfo();
    void verifyTSMessage();

#ifdef USE_SCEP
    void issueSCEP();
    void renewSCEP();
    void getCRLSCEP();
#endif

    void clearLog();

private slots:
    void showRightMenu( QPoint point );

    virtual void dragEnterEvent( QDragEnterEvent *event );
    virtual void dropEvent( QDropEvent *event );

private:

    void setPath( const QString strFilePath );

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();


    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTabWidget      *text_tab_;
    QTextEdit       *log_text_;
    QTextEdit       *info_text_;
    SearchMenu      *search_menu_;

    int             right_type_;
    ManTreeItem     *root_ca_;
    QStackedLayout  *stack_;

    StatForm        *stat_;

    int             openDB( const QString dbPath );
};

#endif // MAINWINDOW_H
