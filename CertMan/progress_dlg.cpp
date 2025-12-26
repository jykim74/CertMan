#include "progress_dlg.h"
#include "man_applet.h"
#include "db_mgr.h"
#include "commons.h"
#include "config_rec.h"
#include "set_pass_dlg.h"
#include "login_dlg.h"

ProgressDlg::ProgressDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mStartBtn, SIGNAL(clicked()), this, SLOT(clickStart()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

ProgressDlg::~ProgressDlg()
{

}

void ProgressDlg::setHead( const QString& strLabel )
{
    mHeadLabel->setText( strLabel );
}

void ProgressDlg::setCmd( int nCmd )
{
    int nCount = 0;
    cmd_ = nCmd;

    switch (cmd_) {
    case kCmdEncPriKey:
        setHead( tr("Encrypt Private") );
        nCount = manApplet->dbMgr()->getKeyPairCountAll();
        setMaxValue( nCount );
        break;
    case kCmdChangeEnc:
        setHead( tr("Change Private Password") );
        nCount = manApplet->dbMgr()->getKeyPairCountAll();
        setMaxValue( nCount );
        break;

    default:
        break;
    }


    return;
}

void ProgressDlg::setMaxValue( int nMax )
{
    mProgBar->setMaximum( nMax );
    mTotalText->setText( QString( "%1" ).arg( nMax ));
}

void ProgressDlg::clickStart()
{
    int ret = -1;

    DBMgr* dbMgr = manApplet->dbMgr();

    ret = dbMgr->beginTransaction();
    if( ret != CKR_OK )
    {
        manApplet->warningBox( tr( "Transaction failed"), this );
        return;
    }

    switch (cmd_) {
    case kCmdEncPriKey:
        ret = runEncryptPrivateKey();
        break;

    case kCmdChangeEnc:
        ret = runChangeEncrypt();
        break;

    default:
        break;
    }

    if( ret == JSR_OK )
        dbMgr->commit();
    else
        dbMgr->rollback();
}

int ProgressDlg::runEncryptPrivateKey()
{
    int ret = -1;
    DBMgr* dbMgr = manApplet->dbMgr();

    int nKeyCount = manApplet->dbMgr()->getKeyPairCountAll();

    SetPassDlg setPassDlg;
    setPassDlg.setHead( tr("Set private key password"));
    setPassDlg.setPassNeed( true );

    if( setPassDlg.exec() != QDialog::Accepted )
        return -1;

    if( setPassDlg.getPasswd().length() < 1 )
    {
        manApplet->warningBox( tr( "Password required" ), this );
        return -1;
    }

    QString strPass = setPassDlg.getPasswd();
    ConfigRec config;
    QString strHMAC = getPasswdHMAC( strPass );

    config.setKind( JS_GEN_KIND_CERTMAN );
    config.setName( "Passwd" );
    config.setValue( strHMAC );

    manApplet->dbMgr()->addConfigRec( config );
    manApplet->setPasswdKey( strPass );

    manApplet->log( QString("Total KeyPair Count: %1").arg( nKeyCount) );
    if( nKeyCount > 0 )
    {
        int ret = 0;
        int nLeftCount = nKeyCount;
        int nLimit = 10;
        int nOffset = 0;
        int nKMIPCount = 0;
        int nPKCS11Count = 0;
        int nCount = 0;

        while( nLeftCount > 0 )
        {
            QList<KeyPairRec> keyPairList;

            ret = dbMgr->getKeyPairList( -1, nOffset, nLimit, keyPairList );

            for( int i = 0; i < keyPairList.size(); i++ )
            {
                KeyPairRec keyPair = keyPairList.at(i);
                QString strKeyAlg = keyPair.getAlg();

                if( isKMIPPrivate( strKeyAlg ) )
                {
                    manApplet->log( QString( "KeyNum(%1) is KIMP Private and Skip" ).arg( keyPair.getNum() ));
                    nKMIPCount++;
                    nCount++;
                }
                else if( isPKCS11Private( strKeyAlg ))
                {
                    manApplet->log( QString( "KeyNum(%1) is PKCS11 Private and Skip" ).arg( keyPair.getNum() ));
                    nPKCS11Count++;
                    nCount++;
                }
                else if( isInternalPrivate( strKeyAlg ) )
                {
                    BIN binPri = {0,0};
                    JS_BIN_decodeHex( keyPair.getPrivateKey().toStdString().c_str(), &binPri);
                    QString strEncPri = manApplet->getEncPriHex( &binPri );
                    if( strEncPri.length() < 1 )
                    {
                        manApplet->elog( QString( "KeyNum(%1) is fail to encrypt").arg( keyPair.getNum() ));
                        ret = JSR_ERR;
                        goto end;
                    }
                    else
                    {
                        ret = dbMgr->modKeyPairPrivate( keyPair.getNum(), strEncPri );
                        if( ret != JSR_OK ) goto end;

                        nCount++;
                        manApplet->log( QString( "KeyNum(%1) is encrypted").arg( keyPair.getNum() ));
                    }

                    JS_BIN_reset( &binPri );
                }
            }

            mProgBar->setValue( nCount );
            mCurrentText->setText( QString("%1").arg( nCount ));
            nOffset += keyPairList.size();
            nLeftCount -= keyPairList.size();
            keyPairList.clear();
        }

        manApplet->log( QString("Set Password KeyPair Total(%1) KMIP(%2) PKCS11(%3) Encrypt(%4)" )
                           .arg( nKeyCount ).arg( nKMIPCount ).arg( nPKCS11Count ).arg( nCount ) );
    }

    manApplet->messageBox( tr( "Set Password successfully" ), this );
    ret = JSR_OK;

end :

    return ret;
}


int ProgressDlg::runChangeEncrypt()
{
    int ret = 0;
    QString strOldPass;
    QString strNewPass;

    BIN binPri = {0,0};

    DBMgr* dbMgr = manApplet->dbMgr();

    LoginDlg loginDlg;
    loginDlg.setHead( tr( "Please enter your current password first" ) );

    if( loginDlg.exec() != QDialog::Accepted )
    {
        return JSR_ERR;
    }

    strOldPass = loginDlg.getPasswd();

    SetPassDlg setPassDlg;
    setPassDlg.setHead( tr("Change private key password"));
    setPassDlg.setPassNeed( true );

    if( setPassDlg.exec() != QDialog::Accepted )
    {
        return JSR_ERR;
    }

    if( setPassDlg.getPasswd().length() < 1 )
    {
        manApplet->warningBox( tr( "Password required" ), this );
        return JSR_ERR;
    }

    strNewPass = setPassDlg.getPasswd();
    QString strHMAC = getPasswdHMAC( strNewPass );
    dbMgr->modConfigRec( JS_GEN_KIND_CERTMAN, "Passwd", strHMAC );

    manApplet->setPasswdKey( strNewPass );

    int nKeyCount = manApplet->dbMgr()->getKeyPairCountAll();

    manApplet->log( QString("Total KeyPair Count: %1").arg( nKeyCount) );

    if( nKeyCount > 0 )
    {
        int ret = 0;
        int nLeftCount = nKeyCount;
        int nKMIPCount = 0;
        int nPKCS11Count = 0;
        int nLimit = 10;
        int nOffset = 0;
        int nCount = 0;

        while( nLeftCount > 0 )
        {
            QList<KeyPairRec> keyPairList;

            ret = dbMgr->getKeyPairList( -1, nOffset, nLimit, keyPairList );

            for( int i = 0; i < keyPairList.size(); i++ )
            {
                KeyPairRec keyPair = keyPairList.at(i);
                QString strKeyAlg = keyPair.getAlg();

                if( isKMIPPrivate( strKeyAlg ) )
                {
                    manApplet->log( QString( "KeyNum(%1) is KIMP Private and Skip" ).arg( keyPair.getNum() ));
                    nKMIPCount++;
                    nCount++;
                }
                else if( isPKCS11Private( strKeyAlg ))
                {
                    manApplet->log( QString( "KeyNum(%1) is PKCS11 Private and Skip" ).arg( keyPair.getNum() ));
                    nPKCS11Count++;
                    nCount++;
                }
                else if( isInternalPrivate( strKeyAlg ) )
                {
                    ret = manApplet->getDecPriBIN( strOldPass, keyPair.getPrivateKey(), &binPri );
                    if( ret != 0 )
                    {
                        manApplet->elog( QString( "KeyNum(%1) is fail to decrypt" ).arg( keyPair.getNum() ));
                        goto end;
                    }

                    QString strEncPri = manApplet->getEncPriHex( &binPri );
                    if( strEncPri.length() < 1 )
                    {
                        manApplet->elog( QString( "KeyNum(%1) is fail to encrypt" ).arg( keyPair.getNum() ));
                        ret = JSR_ERR;
                        goto end;
                    }
                    else
                    {
                        ret = dbMgr->modKeyPairPrivate( keyPair.getNum(), strEncPri );
                        if( ret != JSR_OK ) goto end;
                        manApplet->log( QString( "KeyNum(%1) is changed").arg( keyPair.getNum() ));
                        nCount++;
                    }

                    JS_BIN_reset( &binPri );
                }
            }

            mProgBar->setValue( nCount );
            mCurrentText->setText( QString("%1").arg( nCount ));

            nOffset += keyPairList.size();
            nLeftCount -= keyPairList.size();
            keyPairList.clear();
        }

        manApplet->log( QString("KeyPair Total(%1) KMIP(%2) PKCS11(%3) Change(%4)" )
                           .arg( nKeyCount ).arg( nKMIPCount ).arg( nPKCS11Count ).arg( nCount ) );
    }

    ret = JSR_OK;
    manApplet->messageBox( tr( "Change Password successfully" ), this );
end :
    JS_BIN_reset( &binPri );
    if( ret != JSR_OK )
    {
        manApplet->setPasswdKey( strOldPass );
    }

    return ret;
}
