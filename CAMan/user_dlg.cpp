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

    mCertNumText->setText( "-1" );
    mStatusText->setText( "0" );
}

void UserDlg::accept()
{
    DBMgr* dbMgr = manApplet->mainWindow()->dbMgr();
    if( dbMgr == NULL ) return;

    UserRec     user;

    QString strName = mNameText->text();
    QString strSSN = mSSNText->text();
    QString strEmail = mEmailText->text();
    int nCertNum = mCertNumText->text().toInt();
    int nStatus = mStatusText->text().toInt();
    QString strRefCode = mRefCodeText->text();
    QString strSecretNum = mSecretNumText->text();

    user.setName( strName );
    user.setSSN( strSSN );
    user.setEmail( strEmail );
    user.setCertNum( nCertNum );
    user.setStatus( nStatus );
    user.setRefCode( strRefCode );
    user.setSecretNum( strSecretNum );

    dbMgr->addUserRec( user );

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
