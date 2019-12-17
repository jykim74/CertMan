#include "mainwindow.h"
#include "man_applet.h"
#include "db_mgr.h"

#include "js_bin.h"
#include "js_pki.h"

#include "user_dlg.h"
#include "user_rec.h"

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

    mStatusText->setText( "0" );
}

void UserDlg::accept()
{
    BIN binRef = {0,0};
    char *pHexRef = NULL;

    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    UserRec     user;

    QString strName = mNameText->text();
    QString strSSN = mSSNText->text();
    QString strEmail = mEmailText->text();
    int nStatus = mStatusText->text().toInt();
    QString strRefCode = mRefCodeText->text();
    QString strSecretNum = mSecretNumText->text();

    JS_BIN_set( &binRef, (unsigned char *)strRefCode.toStdString().c_str(), strRefCode.length() );
    JS_BIN_encodeHex( &binRef, &pHexRef );

    user.setName( strName );
    user.setSSN( strSSN );
    user.setEmail( strEmail );
    user.setStatus( nStatus );
    user.setRefCode( pHexRef );
    user.setSecretNum( strSecretNum );

    dbMgr->addUserRec( user );

    JS_BIN_reset( &binRef );
    if( pHexRef ) JS_free( pHexRef );

    QDialog::accept();
    manApplet->mainWindow()->createRightUserList();
}

void UserDlg::getRefCode()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    int nSeq = dbMgr->getSeq( "TB_USER" );

    mRefCodeText->setText( QString("%1").arg( nSeq));
}

void UserDlg::getSecretNum()
{
    BIN binRand = {0,0};
    char    *pRand = NULL;

    JS_PKI_genRandom( 4, &binRand );
    JS_BIN_encodeHex( &binRand, &pRand );

    mSecretNumText->setText( pRand );

    JS_BIN_reset( &binRand );
    if( pRand ) JS_free( pRand );
}

void UserDlg::initUI()
{
    connect( mRefCodeBtn, SIGNAL(clicked()), this, SLOT(getRefCode()));
    connect( mSecretNumBtn, SIGNAL(clicked()), this, SLOT(getSecretNum()));
}

void UserDlg::initialize()
{

}
