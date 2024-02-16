#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_gen.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_json.h"
#include "js_http.h"

#include "user_dlg.h"
#include "user_rec.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "settings_mgr.h"
#include "commons.h"

const QStringList kUserStatus = { "Invalid", "Register", "Issue", "Stop" };

UserDlg::UserDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    initUI();
}

UserDlg::~UserDlg()
{

}

void UserDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void UserDlg::accept()
{
    BIN binRef = {0,0};
    char *pHexRef = NULL;
    time_t now_t = time(NULL);

    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    UserRec     user;

    QString strName = mNameText->text();
    QString strSSN = mSSNText->text();
    QString strEmail = mEmailText->text();
    int nStatus = mStatusCombo->currentIndex();
    QString strRefNum = mRefNumText->text();
    QString strAuthCode = mAuthCodeText->text();

    JS_BIN_set( &binRef, (unsigned char *)strRefNum.toStdString().c_str(), strRefNum.length() );
    JS_BIN_encodeHex( &binRef, &pHexRef );

    user.setRegTime( now_t );
    user.setName( strName );
    user.setSSN( strSSN );
    user.setEmail( strEmail );
    user.setStatus( nStatus );
    user.setRefNum( pHexRef );
    user.setAuthCode( strAuthCode );

    dbMgr->addUserRec( user );

    JS_BIN_reset( &binRef );
    if( pHexRef ) JS_free( pHexRef );

    if( manApplet->isPRO() )
        addAudit( manApplet->dbMgr(), JS_GEN_KIND_CERTMAN, JS_GEN_OP_REG_USER, "" );


    QDialog::accept();
    manApplet->mainWindow()->createRightUserList();
}

void UserDlg::getRefNum()
{
    DBMgr* dbMgr = manApplet->dbMgr();
    if( dbMgr == NULL ) return;

    int nSeq = dbMgr->getLastVal( "TB_USER" );

    mRefNumText->setText( QString("%1").arg( nSeq));
}

void UserDlg::getAuthCode()
{
    BIN binRand = {0,0};
    char    *pRand = NULL;

    JS_PKI_genRandom( 4, &binRand );
    JS_BIN_encodeHex( &binRand, &pRand );

    mAuthCodeText->setText( pRand );

    JS_BIN_reset( &binRand );
    if( pRand ) JS_free( pRand );
}

void UserDlg::initUI()
{
    connect( mRefNumBtn, SIGNAL(clicked()), this, SLOT(getRefNum()));
    connect( mAuthCodeBtn, SIGNAL(clicked()), this, SLOT(getAuthCode()));
    connect( mRegServerBtn, SIGNAL(clicked()), this, SLOT(regServer()));
}

void UserDlg::initialize()
{
    mStatusCombo->addItems( kUserStatus );
    mStatusCombo->setCurrentIndex(1);
}


void UserDlg::regServer()
{
    int ret = 0;
    JRegUserReq     sUserReq;
    JRegUserRsp     sUserRsp;
    char *pReq = NULL;
    char *pRsp = NULL;
    int nStatus = -1;

    memset( &sUserReq, 0x00, sizeof(sUserReq));
    memset( &sUserRsp, 0x00, sizeof(sUserRsp));

    QString strName = mNameText->text();
    QString strSSN = mSSNText->text();
    QString strEmail = mEmailText->text();

    SettingsMgr *mgr = manApplet->settingsMgr();
    QString strToken;

    ret = manApplet->loignRegServer( strToken );
    if( ret != 0 )
    {
        manApplet->warnLog( tr( "Registration server login failure [%1]" ).arg(ret), this );
        return;
    }

    QString strURL;

    if( mgr->REGUse() == false )
    {
        manApplet->warningBox( tr( "There are no REG settings" ), this );
        return;
    }

    strURL = mgr->REGURI();
    strURL += JS_REG_PATH_USER;

    JS_JSON_setRegUserReq( &sUserReq,
                           strName.toStdString().c_str(),
                           strSSN.toStdString().c_str(),
                           strEmail.toStdString().c_str() );

    JS_JSON_encodeRegUserReq( &sUserReq, &pReq );

    ret = JS_HTTP_requestTokenPost( strURL.toStdString().c_str(),
                                   "application/json",
                                   strToken.toStdString().c_str(),
                                   pReq, &nStatus, &pRsp );
    if( ret != 0 )
    {
        manApplet->warnLog( QString( "failed to request HTTP post [%1]" ).arg( ret ));
        goto end;
    }

    JS_JSON_decodeRegUserRsp( pRsp, &sUserRsp );

    if( strcasecmp( sUserRsp.pResCode, "0000" ) == 0 )
    {
        manApplet->messageBox( tr( "User registration successful" ), this );
        manApplet->mainWindow()->createRightUserList();
        ret = 0;
    }
    else
    {
        manApplet->warningBox( tr("User registration fail [%1]").arg(ret), this );
        ret = -1;
    }

end :
    if( pReq ) JS_free( pReq );
    if( pRsp ) JS_free( pRsp );
    JS_JSON_resetRegUserReq( &sUserReq );
    JS_JSON_resetRegUserRsp( &sUserRsp );

    if( ret == 0 )
    {
        QDialog::accept();
        close();
    }
}
