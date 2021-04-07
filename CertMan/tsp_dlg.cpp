#include "tsp_dlg.h"
#include "js_bin.h"
#include "js_tsp.h"
#include "js_http.h"

#include "commons.h"
#include "man_applet.h"
#include "mainwindow.h"

static QStringList sHashList = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };

TSPDlg::TSPDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mHashCombo->addItems( sHashList );

    connect( mSendBtn, SIGNAL(clicked()), this, SLOT(clickSend()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(clickClose()));

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

    JS_BIN_fileRead( mgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binTSPCert );

    if( mSrcStringCheck->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char*)strSrc.toStdString().c_str(), strSrc.length());
    else if( mSrcHexCheck->isChecked() )
        JS_BIN_decodeHex( strSrc.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Check->isChecked() )
        JS_BIN_decodeBase64( strSrc.toStdString().c_str(), &binSrc );

    ret = JS_TSP_encodeRequest( &binSrc, strHash.toStdString().c_str(), pPolicy, &binReq );
    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );
    ret = JS_TSP_decodeResponse( &binRsp, &binTSPCert, &binData, &sTSTInfo );

    JS_BIN_encodeHex( &binData, &pHex );
    if( pHex )
    {
        mOutputText->setPlainText( pHex );
        JS_free( pHex );
    }

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