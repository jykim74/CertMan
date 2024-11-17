/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QTreeView>
#include <QTableWidget>
#include <QTextEdit>
#include <QtSql>
#include <QStackedLayout>

#include "js_bin.h"
#include "code_editor.h"


class ManTreeView;
class ManTreeModel;
class ManTreeItem;
class SearchForm;
class CertRec;

#ifdef _ENABLE_CHARTS
class StatForm;
#endif

class ProfileExtRec;

class PKISrvDlg;

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

    void useLog( bool bEnable = true );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
    void info( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void infoClear();
    void infoCursorTop();

    void createActions();
    void createViewActions();
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
    void createRightConfigList( int nKind = -1 );
    void createRightUserList();
    void createRightKMSList();
    void createRightSignerList(int nType);
#ifdef _ENABLE_CHARTS
    void createRightStatistics();
#endif
    void createRightAuditList();
    void createRightTSPList();

    void removeAllRight();

    void infoLine();
    void infoKeyPair( int seq );
    void infoRequest( int seq );
    void infoCertificate( int seq );
    void infoCertProfile( int seq );
    void infoProfileExt( ProfileExtRec& profileExt );
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
    void viewCertProfile();
    void copyCertProfile();
    void editCRLProfile();
    void viewCRLProfile();
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
    void serverConfig();

    void viewCertificate();
    void viewCRL();
    void verifyCRL();
    void viewPriKey();
    void viewCSR();

    void importData();
    void importCert();
    void importCRL();
    void importCSR();
    void importPriKey();
    void importEncPriKey();
    void exportPriKey();
    void exportPubKey();
    void exportRequest();
    void exportCertificate();
    void exportCRL();
    void exportPriKeyAndCert();
    void setPasswd();
    void changePasswd();

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
    void getURI();
    void expandMenu();
    void expandItem( ManTreeItem *item );
    void licenseInfo();
    void bugIssueReport();
    void qnaDiscussion();
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
    void toggleLog();

    void OCSPSrv();
    void TSPSrv();
    void CMPSrv();
    void RegSrv();
    void CCSrv();
    void KMSSrv();

private slots:
    void showRightMenu( QPoint point );
    void doubleClickRightTable(QModelIndex index);

    virtual void dragEnterEvent( QDragEnterEvent *event );
    virtual void dropEvent( QDropEvent *event );
    void closeEvent(QCloseEvent *event);

private:

    void adjustForCurrentFile( const QString& filePath );
    void updateRecentActionList();
    int openDB( const QString dbPath );

    int saveKeyPair( const QString strName, const BIN *pPubInfo, const BIN *pPri );

    bool isView( int nAct );
    void setView( int nAct );
    void unsetView( int nAct );

    void viewFileNew( bool bChecked );
    void viewFileOpen( bool bChecked );
    void viewFileRemoteDB( bool bChecked );
    void viewFileLogout( bool bChecked );
    void viewFileQuit( bool bChecked );

    void viewToolNewKey( bool bChecked );
    void viewToolMakeReq( bool bChecked );
    void viewToolMakeConfig( bool bChecked );
    void viewToolRegUser( bool bChecked );
    void viewToolRegSigner( bool bChecked );
    void viewToolMakeCertProfile( bool bChecked );
    void viewToolMakeCRLProfile( bool bChecked );
    void viewToolMakeCert( bool bChecked );
    void viewToolMakeCRL( bool bChecked );
    void viewToolRevokeCert( bool bChecked );

    void viewDataImportData( bool bChecked );
    void viewDataGetURI( bool bChecked );
    void viewDataPublishLDAP( bool bChecked );
    void viewDataSetPasswd( bool bChecked );
    void viewDataChangePasswd( bool bChecked );
    void viewDataTSPClient( bool bChecked );

    void viewServerOCSP( bool bChecked );
    void viewServerTSP( bool bChecked );
    void viewServerCMP( bool bChecked );
    void viewServerREG( bool bChecked );
    void viewServerCC( bool bChecked );
    void viewServerKMS( bool bChecked );

    void viewHelpServerStatus( bool bChecked );
    void viewHelpSetting( bool bChecked );
    void viewHelpClearLog( bool bChecked );
    void viewHelpHaltLog( bool bChecked );
    void viewHelpAbout( bool bChecked );

    void viewSetDefault();

    QList<QAction *>  recent_file_list_;

    QSplitter       *hsplitter_;
    QSplitter       *vsplitter_;

    ManTreeView     *left_tree_;
    ManTreeModel    *left_model_;
    QTableWidget    *right_table_;
    QTabWidget      *text_tab_;
    QPlainTextEdit  *log_text_;
    CodeEditor      *info_text_;
    SearchForm      *search_form_;

    int             right_type_;
    ManTreeItem     *root_ca_;

#ifdef _ENABLE_CHARTS
    QStackedLayout  *stack_;
    StatForm        *stat_;
#endif

    bool            log_halt_;

    PKISrvDlg       *pki_srv_;

    QToolBar*       file_tool_;
    QAction*        new_act_;
    QAction*        open_act_;
    QAction*        remote_db_act_;
    QAction*        logout_act_;
    QAction*        quit_act_;

    QToolBar*       tool_tool_;
    QAction*        new_key_act_;
    QAction*        make_req_act_;
    QAction*        make_config_act_;
    QAction*        reg_user_act_;
    QAction*        reg_signer_act_;
    QAction*        make_cert_profile_act_;
    QAction*        make_crl_profile_act_;
    QAction*        make_cert_act_;
    QAction*        make_crl_act_;
    QAction*        revoke_cert_act_;

    QToolBar*       data_tool_;
    QAction*        import_data_act_;
    QAction*        get_uri_act_;
    QAction*        publish_ldap_act_;
    QAction*        set_passwd_act_;
    QAction*        change_passwd_act_;
    QAction*        tsp_client_act_;

    QToolBar*       server_tool_;
    QAction*        ocsp_act_;
    QAction*        tsp_act_;
    QAction*        cmp_act_;
    QAction*        reg_act_;
    QAction*        cc_act_;
    QAction*        kms_act_;

    QToolBar*       help_tool_;
    QAction*        server_status_act_;
    QAction*        setting_act_;
    QAction*        clear_log_act_;
    QAction*        halt_log_act_;
    QAction*        lcn_info_act_;
    QAction*        bug_issue_act_;
    QAction*        qna_act_;
    QAction*        about_act_;
};

#endif // MAINWINDOW_H
