#include "tsp_dlg.h"
#include "js_bin.h"
#include "js_tsp.h"
#include "js_http.h"
#include "js_pkcs7.h"

#include "commons.h"
#include "man_applet.h"
#include "mainwindow.h"
#include "tst_info_dlg.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };

TSPDlg::TSPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mHashCombo->addItems( sHashList );

    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));
    connect( mViewTSTInfoBtn, SIGNAL(clicked()), this, SLOT(clickViewTSTInfo()));
    connect( mVerifyTSPBtn, SIGNAL(clicked()), this, SLOT(clickVerifyTSP()));

    mCloseBtn->setFocus();
}

TSPDlg::~TSPDlg()
{

}

void TSPDlg::clickSend()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binTSPCert = {0,0};
    BIN binData = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    JTSTInfo    sTSTInfo;

    int nStatus = 0;
    QString strURL;
    char *pHex = NULL;

    const char *pPolicy = "1.2.3.4";

    SettingsMgr *mgr = manApplet->settingsMgr();

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    if( mgr->TSPUse() == false )
    {
        manApplet->warningBox( tr( "TSP service is not set" ), this );
        return;
    }

    QString strSrc = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();

    strURL = mgr->TSPURI();
    strURL += "/TSP";

    ret = JS_BIN_fileReadBER( mgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binTSPCert );
    if( ret <= 0 )
    {
        manApplet->warningBox( tr( "fail to read TSP Server certificate"), this );
        return;
    }

    if( mSrcStringCheck->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char*)strSrc.toStdString().c_str(), strSrc.length());
    else if( mSrcHexCheck->isChecked() )
        JS_BIN_decodeHex( strSrc.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Check->isChecked() )
        JS_BIN_decodeBase64( strSrc.toStdString().c_str(), &binSrc );

    ret = JS_TSP_encodeRequest( &binSrc, strHash.toStdString().c_str(), pPolicy, &binReq );
    if( ret != 0 )
    {
        manApplet->elog( QString("fail to encode request: %1").arg( ret ));
        goto end;
    }

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to post request: %1").arg( ret ));
        goto end;
    }

    ret = JS_TSP_verifyResponse( &binRsp, &binTSPCert, &binData, &sTSTInfo );
    if( ret != 0 )
    {
        manApplet->elog( QString( "fail to verify response: %1").arg(ret));
        goto end;
    }

    mOutputText->setPlainText( getHexString( &binRsp ) );
/*
    JS_BIN_encodeHex( &binData, &pHex );
    if( pHex )
    {
        mOutputText->setPlainText( pHex );
        JS_free( pHex );
    }
*/

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binTSPCert );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
}

void TSPDlg::clickClose()
{
    close();
}

void TSPDlg::clickViewTSTInfo()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binTST = {0,0};
    BIN binRsp = {0,0};

    TSTInfoDlg tstInfoDlg;

    QString strOut = mOutputText->toPlainText();
    if( strOut.length() < 1 )
    {
        manApplet->warningBox( tr( "There is no TSP response" ), this );
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &binData, &binTST );
    if( ret != 0 )
    {
        manApplet->warningBox(tr( "fail to decode TSP response"), this );
        goto end;
    }


    tstInfoDlg.setTST( &binTST );
    tstInfoDlg.exec();

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
}

void TSPDlg::clickVerifyTSP()
{
    int ret = 0;
    BIN binData = {0,0};
    BIN binTST = {0,0};
    BIN binRsp = {0,0};
    BIN binCert = {0,0};

    SettingsMgr *smgr = manApplet->settingsMgr();
    QString strVerify;

    QString strOut = mOutputText->toPlainText();
    if( strOut.length() < 1 )
    {
        manApplet->warningBox( tr( "There is no TSP response" ), this );
        return;
    }

    JS_BIN_decodeHex( strOut.toStdString().c_str(), &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &binData, &binTST );
    if( ret != 0 )
    {
        manApplet->warningBox(tr( "fail to decode TSP response"), this );
        goto end;
    }

    if( smgr->TSPUse() )
    {
        ret = JS_BIN_fileReadBER( smgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( ret <= 0 )
        {
            manApplet->warningBox( tr( "fail to read TSP Server certificate" ), this );
            goto end;
        }
    }

    ret = JS_PKCS7_verifySignedData( &binData, &binCert, &binData );
    strVerify = QString( "Verify val:%1" ).arg( ret );

    manApplet->messageBox( strVerify, this );

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
    JS_BIN_reset( &binCert );
}
