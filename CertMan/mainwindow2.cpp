#include <QMenu>
#include <QMenuBar>
#include <QToolBar>

#include "commons.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "settings_mgr.h"

bool MainWindow::isView( int nAct )
{
    int nValue = -1;
    int nType = nAct & 0xFF000000;

    if( manApplet->isLicense() )
        nValue = manApplet->settingsMgr()->viewValue( nType );
    else
    {
        switch (nType) {
        case VIEW_FILE:
            nValue = kFileDefault;
            break;
        case VIEW_TOOL:
            nValue = kToolDefault;
            break;
        case VIEW_DATA:
            nValue = kDataDefault;
            break;
        case VIEW_SERVER:
            nValue = kServerDefault;
            break;
        case VIEW_HELP:
            nValue = kHelpDefault;
            break;
        default:
            break;
        }
    }

    if( nValue < 0 ) return false;

    if( (nValue & nAct) == nAct )
        return true;

    return false;
}

void MainWindow::setView( int nAct )
{
    int nType = nAct & 0xFF000000;

    int nValue = manApplet->settingsMgr()->getViewValue( nType );
    if( nValue < 0 ) return;

    nValue |= nAct;

    manApplet->settingsMgr()->setViewValue( nValue );
}

void MainWindow::unsetView( int nAct )
{
    int nType = nAct & 0xFF000000;

    int nValue = manApplet->settingsMgr()->getViewValue( nType );
    if( nValue < 0 ) return;

    if( nValue & nAct ) nValue -= nAct;

    nValue |= nType;

    manApplet->settingsMgr()->setViewValue( nValue );
}

void MainWindow::createViewActions()
{
    bool bVal = false;
    QMenu *viewMenu = menuBar()->addMenu( tr("&View" ));

    QMenu *fileMenu = viewMenu->addMenu( tr("File ToolBar") );
    viewMenu->addSeparator();

    QMenu *toolMenu = viewMenu->addMenu( tr("Tool ToolBar"));
    QMenu *dataMenu = viewMenu->addMenu( tr( "Data ToolBar" ) );
    QMenu *serverMenu = NULL;

    if( manApplet->isPRO() )
    {
        serverMenu = viewMenu->addMenu( tr( "Server ToolBar" ));
    }

    QMenu *helpMenu = viewMenu->addMenu( tr( "Help ToolBar" ));

    QAction *fileNewAct = new QAction( tr( "New"), this );
    bVal = isView( ACT_FILE_NEW );
    fileNewAct->setCheckable( true );
    fileNewAct->setChecked( bVal );
    connect( fileNewAct, &QAction::triggered, this, &MainWindow::viewFileNew );
    fileMenu->addAction( fileNewAct );

    QAction *fileOpenAct = new QAction( tr( "Open" ), this );
    bVal = isView( ACT_FILE_OPEN );
    fileOpenAct->setCheckable( true );
    fileOpenAct->setChecked( bVal );
    connect( fileOpenAct, &QAction::triggered, this, &MainWindow::viewFileOpen );
    fileMenu->addAction( fileOpenAct );

    QAction *fileRemoteDBAct = new QAction( tr( "Remote Database" ), this );
    bVal = isView( ACT_FILE_REMOTE_DB );
    fileRemoteDBAct->setCheckable( true );
    fileRemoteDBAct->setChecked( bVal );
    connect( fileRemoteDBAct, &QAction::triggered, this, &MainWindow::viewFileRemoteDB );
    fileMenu->addAction( fileRemoteDBAct );

    QAction *fileLogoutAct = new QAction( tr( "Logout" ), this );
    bVal = isView( ACT_FILE_LOGOUT );
    fileLogoutAct->setCheckable( true );
    fileLogoutAct->setChecked( bVal );
    connect( fileLogoutAct, &QAction::triggered, this, &MainWindow::viewFileLogout );
    fileMenu->addAction( fileLogoutAct );

    QAction *toolNewKeyAct = new QAction( tr( "New Key" ), this );
    bVal = isView( ACT_TOOL_NEW_KEY );
    toolNewKeyAct->setCheckable( true );
    toolNewKeyAct->setChecked( bVal );
    connect( toolNewKeyAct, &QAction::triggered, this, &MainWindow::viewToolNewKey );
    toolMenu->addAction( toolNewKeyAct );

    QAction *toolMakeReqAct = new QAction( tr( "Make Request" ), this );
    bVal = isView( ACT_TOOL_MAKE_REQ );
    toolMakeReqAct->setCheckable( true );
    toolMakeReqAct->setChecked( bVal );
    connect( toolMakeReqAct, &QAction::triggered, this, &MainWindow::viewToolMakeReq );
    toolMenu->addAction( toolMakeReqAct );

    QAction *toolMakeConfigAct = new QAction( tr( "Make Config" ), this );
    bVal = isView( ACT_TOOL_MAKE_CONFIG );
    toolMakeConfigAct->setCheckable( true );
    toolMakeConfigAct->setChecked( bVal );
    connect( toolMakeConfigAct, &QAction::triggered, this, &MainWindow::viewToolMakeConfig );
    toolMenu->addAction( toolMakeConfigAct );

    QAction *toolRegUserAct = new QAction( tr( "Register User" ), this );
    bVal = isView( ACT_TOOL_REG_USER );
    toolRegUserAct->setCheckable( true );
    toolRegUserAct->setChecked( bVal );
    connect( toolRegUserAct, &QAction::triggered, this, &MainWindow::viewToolRegUser );
    toolMenu->addAction( toolRegUserAct );

    QAction *toolRegSignerAct = new QAction( tr( "Register Signer" ), this );
    bVal = isView( ACT_TOOL_REG_SIGNER );
    toolRegSignerAct->setCheckable( true );
    toolRegSignerAct->setChecked( bVal );
    connect( toolRegSignerAct, &QAction::triggered, this, &MainWindow::viewToolRegSigner );
    toolMenu->addAction( toolRegSignerAct );

    QAction *toolMakeCertProfileAct = new QAction( tr( "Make Cert Profile" ), this );
    bVal = isView( ACT_TOOL_MAKE_CERT_PROFILE );
    toolMakeCertProfileAct->setCheckable( true );
    toolMakeCertProfileAct->setChecked( bVal );
    connect( toolMakeCertProfileAct, &QAction::triggered, this, &MainWindow::viewToolMakeCertProfile );
    toolMenu->addAction( toolMakeCertProfileAct );

    QAction *toolMakeCRLProfileAct = new QAction( tr( "Make CRL Profile" ), this );
    bVal = isView( ACT_TOOL_MAKE_CRL_PROFILE );
    toolMakeCRLProfileAct->setCheckable( true );
    toolMakeCRLProfileAct->setChecked( bVal );
    connect( toolMakeCRLProfileAct, &QAction::triggered, this, &MainWindow::viewToolMakeCRLProfile );
    toolMenu->addAction( toolMakeCRLProfileAct );

    QAction *toolMakeCertAct = new QAction( tr( "Make Certificate" ), this );
    bVal = isView( ACT_TOOL_MAKE_CERT );
    toolMakeCertAct->setCheckable( true );
    toolMakeCertAct->setChecked( bVal );
    connect( toolMakeCertAct, &QAction::triggered, this, &MainWindow::viewToolMakeCert );
    toolMenu->addAction( toolMakeCertAct );

    QAction *toolMakeCRLAct = new QAction( tr( "Make CRL" ), this );
    bVal = isView( ACT_TOOL_MAKE_CRL );
    toolMakeCRLAct->setCheckable( true );
    toolMakeCRLAct->setChecked( bVal );
    connect( toolMakeCRLAct, &QAction::triggered, this, &MainWindow::viewToolMakeCRL );
    toolMenu->addAction( toolMakeCRLAct );

    QAction *toolRevokeCertAct = new QAction( tr( "Revoke Certificate" ), this );
    bVal = isView( ACT_TOOL_REVOKE_CERT );
    toolRevokeCertAct->setCheckable( true );
    toolRevokeCertAct->setChecked( bVal );
    connect( toolRevokeCertAct, &QAction::triggered, this, &MainWindow::viewToolRevokeCert );
    toolMenu->addAction( toolRevokeCertAct );

    QAction *dataImportDataAct = new QAction( tr( "Import Data" ), this );
    bVal = isView( ACT_DATA_IMPORT_DATA );
    dataImportDataAct->setCheckable( true );
    dataImportDataAct->setChecked( bVal );
    connect( dataImportDataAct, &QAction::triggered, this, &MainWindow::viewDataImportData );
    dataMenu->addAction( dataImportDataAct );

    QAction *dataGetURIAct = new QAction( tr( "Get URI" ), this );
    bVal = isView( ACT_DATA_GET_URI );
    dataGetURIAct->setCheckable( true );
    dataGetURIAct->setChecked( bVal );
    connect( dataGetURIAct, &QAction::triggered, this, &MainWindow::viewDataGetURI );
    dataMenu->addAction( dataGetURIAct );

    QAction *dataPublishLDAPAct = new QAction( tr( "Publish LDAP" ), this );
    bVal = isView( ACT_DATA_PUBLISH_LDAP );
    dataPublishLDAPAct->setCheckable( true );
    dataPublishLDAPAct->setChecked( bVal );
    connect( dataPublishLDAPAct, &QAction::triggered, this, &MainWindow::viewDataPublishLDAP );
    dataMenu->addAction( dataPublishLDAPAct );

    QAction *dataSetPasswdAct = new QAction( tr( "Set Password" ), this );
    bVal = isView( ACT_DATA_SET_PASSWD );
    dataSetPasswdAct->setCheckable( true );
    dataSetPasswdAct->setChecked( bVal );
    connect( dataSetPasswdAct, &QAction::triggered, this, &MainWindow::viewDataSetPasswd );
    dataMenu->addAction( dataSetPasswdAct );

    QAction *dataChangePasswdAct = new QAction( tr( "Change Password" ), this );
    bVal = isView( ACT_DATA_CHANGE_PASSWD );
    dataChangePasswdAct->setCheckable( true );
    dataChangePasswdAct->setChecked( bVal );
    connect( dataChangePasswdAct, &QAction::triggered, this, &MainWindow::viewDataChangePasswd );
    dataMenu->addAction( dataChangePasswdAct );

    if( manApplet->isPRO() )
    {
        QAction *dataTSPClientAct = new QAction( tr( "TSP Client" ), this );
        bVal = isView( ACT_DATA_IMPORT_DATA );
        dataTSPClientAct->setCheckable( true );
        dataTSPClientAct->setChecked( bVal );
        connect( dataTSPClientAct, &QAction::triggered, this, &MainWindow::viewDataTSPClient );
        dataMenu->addAction( dataTSPClientAct );


        QAction *serverOCSPAct = new QAction( tr( "OCSP Server" ), this );
        bVal = isView( ACT_SERVER_OCSP );
        serverOCSPAct->setCheckable( true );
        serverOCSPAct->setChecked( bVal );
        connect( serverOCSPAct, &QAction::triggered, this, &MainWindow::viewServerOCSP );
        serverMenu->addAction( serverOCSPAct );

        QAction *serverTSPAct = new QAction( tr( "TSP Server" ), this );
        bVal = isView( ACT_SERVER_TSP );
        serverTSPAct->setCheckable( true );
        serverTSPAct->setChecked( bVal );
        connect( serverTSPAct, &QAction::triggered, this, &MainWindow::viewServerTSP );
        serverMenu->addAction( serverTSPAct );

        QAction *serverCMPAct = new QAction( tr( "CMP Server" ), this );
        bVal = isView( ACT_SERVER_CMP );
        serverCMPAct->setCheckable( true );
        serverCMPAct->setChecked( bVal );
        connect( serverCMPAct, &QAction::triggered, this, &MainWindow::viewServerCMP );
        serverMenu->addAction( serverCMPAct );

        QAction *serverREGAct = new QAction( tr( "REG Server" ), this );
        bVal = isView( ACT_SERVER_REG );
        serverREGAct->setCheckable( true );
        serverREGAct->setChecked( bVal );
        connect( serverREGAct, &QAction::triggered, this, &MainWindow::viewServerREG );
        serverMenu->addAction( serverREGAct );

        QAction *serverCCAct = new QAction( tr( "CC Server" ), this );
        bVal = isView( ACT_SERVER_CC );
        serverCCAct->setCheckable( true );
        serverCCAct->setChecked( bVal );
        connect( serverCCAct, &QAction::triggered, this, &MainWindow::viewServerCC );
        serverMenu->addAction( serverCCAct );

        QAction *serverKMSAct = new QAction( tr( "KMS Server" ), this );
        bVal = isView( ACT_SERVER_KMS );
        serverKMSAct->setCheckable( true );
        serverKMSAct->setChecked( bVal );
        connect( serverKMSAct, &QAction::triggered, this, &MainWindow::viewServerKMS );
        serverMenu->addAction( serverKMSAct );
    }

    QAction *helpServerStatusAct = new QAction( tr( "Server Status" ), this );
    bVal = isView( ACT_HELP_SERVER_STATUS );
    helpServerStatusAct->setCheckable( true );
    helpServerStatusAct->setChecked( bVal );
    connect( helpServerStatusAct, &QAction::triggered, this, &MainWindow::viewHelpServerStatus );
    helpMenu->addAction( helpServerStatusAct );

    QAction *helpSettingAct = new QAction( tr( "Setting" ), this );
    bVal = isView( ACT_HELP_SETTING );
    helpSettingAct->setCheckable( true );
    helpSettingAct->setChecked( bVal );
    connect( helpSettingAct, &QAction::triggered, this, &MainWindow::viewHelpSetting );
    helpMenu->addAction( helpSettingAct );

    QAction *helpClearLogAct = new QAction( tr( "Clear Log" ), this );
    bVal = isView( ACT_HELP_CLEAR_LOG );
    helpClearLogAct->setCheckable( true );
    helpClearLogAct->setChecked( bVal );
    connect( helpClearLogAct, &QAction::triggered, this, &MainWindow::viewHelpClearLog );
    helpMenu->addAction( helpClearLogAct );

    QAction *helpHaltLogAct = new QAction( tr( "Halt Log" ), this );
    bVal = isView( ACT_HELP_HALT_LOG );
    helpHaltLogAct->setCheckable( true );
    helpHaltLogAct->setChecked( bVal );
    connect( helpHaltLogAct, &QAction::triggered, this, &MainWindow::viewHelpHaltLog );
    helpMenu->addAction( helpHaltLogAct );

    QAction *helpAboutAct = new QAction( tr( "About" ), this );
    bVal = isView( ACT_HELP_ABOUT );
    helpAboutAct->setCheckable( true );
    helpAboutAct->setChecked( bVal );
    connect( helpAboutAct, &QAction::triggered, this, &MainWindow::viewHelpAbout );
    helpMenu->addAction( helpAboutAct );

    viewMenu->addSeparator();
    QAction *setDefaultAct = new QAction( tr( "Set Default" ), this );
    connect( setDefaultAct, &QAction::triggered, this, &MainWindow::viewSetDefault );
    viewMenu->addAction( setDefaultAct );
}

void MainWindow::viewFileNew( bool bChecked )
{
    int nAct = ACT_FILE_NEW;

    if( bChecked == true )
    {
        file_tool_->addAction( new_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( new_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewFileOpen( bool bChecked )
{
    int nAct = ACT_FILE_OPEN;

    if( bChecked == true )
    {
        file_tool_->addAction( open_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( open_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewFileRemoteDB( bool bChecked )
{
    int nAct = ACT_FILE_REMOTE_DB;

    if( bChecked == true )
    {
        file_tool_->addAction( remote_db_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( remote_db_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewFileLogout( bool bChecked )
{
    int nAct = ACT_FILE_LOGOUT;

    if( bChecked == true )
    {
        file_tool_->addAction( logout_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( logout_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewFileQuit( bool bChecked )
{
    int nAct = ACT_FILE_QUIT;

    if( bChecked == true )
    {
        file_tool_->addAction( quit_act_ );
        setView( nAct );
    }
    else
    {
        file_tool_->removeAction( quit_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewToolNewKey( bool bChecked )
{
    int nAct = ACT_TOOL_NEW_KEY;

    if( bChecked == true )
    {
        tool_tool_->addAction( new_key_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( new_key_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeReq( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_REQ;

    if( bChecked == true )
    {
        tool_tool_->addAction( make_req_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_req_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeConfig( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_CONFIG;

    if( bChecked == true )
    {
        tool_tool_->addAction( make_config_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_config_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolRegUser( bool bChecked )
{
    int nAct = ACT_TOOL_REG_USER;

    if( bChecked == true )
    {
        tool_tool_->addAction( reg_user_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( reg_user_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolRegSigner( bool bChecked )
{
    int nAct = ACT_TOOL_REG_SIGNER;

    if( bChecked == true )
    {
        tool_tool_->addAction( reg_signer_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( reg_signer_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeCertProfile( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_CERT_PROFILE;

    if( bChecked == true )
    {
        tool_tool_->addAction( make_cert_profile_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_cert_profile_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeCRLProfile( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_CRL_PROFILE;

    if( bChecked == true )
    {
        tool_tool_->addAction( make_crl_profile_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_crl_profile_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeCert( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_CERT;

    if( bChecked == true )
    {
        tool_tool_->addAction( make_cert_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_cert_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolMakeCRL( bool bChecked )
{
    int nAct = ACT_TOOL_MAKE_CRL;

    if( bChecked == true )
    {
        tool_tool_->addAction( make_crl_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( make_crl_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewToolRevokeCert( bool bChecked )
{
    int nAct = ACT_TOOL_REVOKE_CERT;

    if( bChecked == true )
    {
        tool_tool_->addAction( revoke_cert_act_ );
        setView( nAct );
    }
    else
    {
        tool_tool_->removeAction( revoke_cert_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewDataImportData( bool bChecked )
{
    int nAct = ACT_DATA_IMPORT_DATA;

    if( bChecked == true )
    {
        data_tool_->addAction( import_data_act_ );
        setView( nAct );
    }
    else
    {
        data_tool_->removeAction( import_data_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewDataGetURI( bool bChecked )
{
    int nAct = ACT_DATA_GET_URI;

    if( bChecked == true )
    {
        data_tool_->addAction( get_uri_act_ );
        setView( nAct );
    }
    else
    {
        data_tool_->removeAction( get_uri_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewDataPublishLDAP( bool bChecked )
{
    int nAct = ACT_DATA_PUBLISH_LDAP;

    if( bChecked == true )
    {
        data_tool_->addAction( publish_ldap_act_ );
        setView( nAct );
    }
    else
    {
        data_tool_->removeAction( publish_ldap_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewDataSetPasswd( bool bChecked )
{
    int nAct = ACT_DATA_SET_PASSWD;

    if( bChecked == true )
    {
        data_tool_->addAction( set_passwd_act_ );
        setView( nAct );
    }
    else
    {
        data_tool_->removeAction( set_passwd_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewDataChangePasswd( bool bChecked )
{
    int nAct = ACT_DATA_CHANGE_PASSWD;

    if( bChecked == true )
    {
        data_tool_->addAction( change_passwd_act_ );
        setView( nAct );
    }
    else
    {
        data_tool_->removeAction( change_passwd_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewDataTSPClient( bool bChecked )
{
    int nAct = ACT_DATA_TSP_CLIENT;

    if( bChecked == true )
    {
        data_tool_->addAction( tsp_client_act_ );
        setView( nAct );
    }
    else
    {
        data_tool_->removeAction( tsp_client_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewServerOCSP( bool bChecked )
{
    int nAct = ACT_SERVER_OCSP;

    if( bChecked == true )
    {
        server_tool_->addAction( ocsp_act_ );
        setView( nAct );
    }
    else
    {
        server_tool_->removeAction( ocsp_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewServerTSP( bool bChecked )
{
    int nAct = ACT_SERVER_TSP;

    if( bChecked == true )
    {
        server_tool_->addAction( tsp_act_ );
        setView( nAct );
    }
    else
    {
        server_tool_->removeAction( tsp_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewServerCMP( bool bChecked )
{
    int nAct = ACT_SERVER_CMP;

    if( bChecked == true )
    {
        server_tool_->addAction( cmp_act_ );
        setView( nAct );
    }
    else
    {
        server_tool_->removeAction( cmp_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewServerREG( bool bChecked )
{
    int nAct = ACT_SERVER_REG;

    if( bChecked == true )
    {
        server_tool_->addAction( reg_act_ );
        setView( nAct );
    }
    else
    {
        server_tool_->removeAction( reg_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewServerCC( bool bChecked )
{
    int nAct = ACT_SERVER_CC;

    if( bChecked == true )
    {
        server_tool_->addAction( cc_act_ );
        setView( nAct );
    }
    else
    {
        server_tool_->removeAction( cc_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewServerKMS( bool bChecked )
{
    int nAct = ACT_SERVER_KMS;

    if( bChecked == true )
    {
        server_tool_->addAction( kms_act_ );
        setView( nAct );
    }
    else
    {
        server_tool_->removeAction( kms_act_ );
        unsetView( nAct );
    }
}


void MainWindow::viewHelpServerStatus( bool bChecked )
{
    int nAct = ACT_HELP_SERVER_STATUS;

    if( bChecked == true )
    {
        help_tool_->addAction( server_status_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( server_status_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpSetting( bool bChecked )
{
    int nAct = ACT_HELP_SETTING;

    if( bChecked == true )
    {
        help_tool_->addAction( setting_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( setting_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpClearLog( bool bChecked )
{
    int nAct = ACT_HELP_CLEAR_LOG;

    if( bChecked == true )
    {
        help_tool_->addAction( clear_log_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( clear_log_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpHaltLog( bool bChecked )
{
    int nAct = ACT_HELP_HALT_LOG;

    if( bChecked == true )
    {
        help_tool_->addAction( halt_log_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( halt_log_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewHelpAbout( bool bChecked )
{
    int nAct = ACT_HELP_ABOUT;

    if( bChecked == true )
    {
        help_tool_->addAction( about_act_ );
        setView( nAct );
    }
    else
    {
        help_tool_->removeAction( about_act_ );
        unsetView( nAct );
    }
}

void MainWindow::viewSetDefault()
{
    bool bVal = manApplet->yesOrCancelBox( tr( "Would you like to change to the initial toolbar view?"), this, true );
    if( bVal == false ) return;

    manApplet->settingsMgr()->clearViewValue(VIEW_FILE);
    manApplet->settingsMgr()->clearViewValue(VIEW_TOOL);
    manApplet->settingsMgr()->clearViewValue(VIEW_DATA);
    manApplet->settingsMgr()->clearViewValue(VIEW_SERVER);
    manApplet->settingsMgr()->clearViewValue(VIEW_HELP);

    bVal = manApplet->yesOrNoBox(tr("You have changed toolbar settings. Restart to apply it?"), this, false);
    if( bVal == false ) return;

    manApplet->restartApp();
}
