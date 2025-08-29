/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
    connect( mSrcStringCheck, SIGNAL(clicked()), this, SLOT(changeSrc()));
    connect( mSrcHexCheck, SIGNAL(clicked()), this, SLOT(changeSrc()));
    connect( mSrcBase64Check, SIGNAL(clicked()), this, SLOT(changeSrc()));

    connect( mSrcText, SIGNAL(textChanged()), this, SLOT(changeSrc()));
    connect( mOutputText, SIGNAL(textChanged()), this, SLOT(changeOutput()));

    initialize();

    mSendBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

TSPDlg::~TSPDlg()
{

}

void TSPDlg::initialize()
{
    mPolicyText->setText( "1.2.3.4" );
}

void TSPDlg::changeSrc()
{
    int nType = DATA_HEX;

    if( mSrcStringCheck->isChecked() )
        nType = DATA_STRING;
    else if( mSrcBase64Check->isChecked() )
        nType = DATA_BASE64;

    QString strSrc = mSrcText->toPlainText();
    QString strLen = getDataLenString( nType, strSrc );
    mSrcLenText->setText( QString("%1").arg( strLen ));
}

void TSPDlg::changeOutput()
{
    QString strOutput = mOutputText->toPlainText();
    QString strLen = getDataLenString( DATA_HEX, strOutput );
    mOutputLenText->setText( QString("%1").arg( strLen ));
}

void TSPDlg::clickSend()
{
    int ret = 0;
    BIN binSrc = {0,0};
    BIN binTSPCert = {0,0};
    BIN binData = {0,0};
    BIN binReq = {0,0};
    BIN binRsp = {0,0};
    BIN binTST = {0,0};

    JTSTInfo    sTSTInfo;

    int nStatus = 0;
    QString strURL;

    QString strPolicy = mPolicyText->text();

    SettingsMgr *mgr = manApplet->settingsMgr();

    memset( &sTSTInfo, 0x00, sizeof(sTSTInfo));

    if( mgr->TSPUse() == false )
    {
        manApplet->warningBox( tr( "There are no TSP settings" ), this );
        return;
    }

    QString strSrc = mSrcText->toPlainText();
    QString strHash = mHashCombo->currentText();

    if( strSrc.length() < 1 )
    {
        manApplet->warningBox( tr( "Enter a source value"), this );
        mSrcText->setFocus();
        return;
    }

    strURL = mgr->TSPURI();
    strURL += "/TSP";

    ret = JS_BIN_fileReadBER( mgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binTSPCert );
    if( ret <= 0 )
    {
        manApplet->warningBox( tr( "failed to read TSP Server certificate"), this );
        return;
    }

    if( mSrcStringCheck->isChecked() )
        JS_BIN_set( &binSrc, (unsigned char*)strSrc.toStdString().c_str(), strSrc.length());
    else if( mSrcHexCheck->isChecked() )
        JS_BIN_decodeHex( strSrc.toStdString().c_str(), &binSrc );
    else if( mSrcBase64Check->isChecked() )
        JS_BIN_decodeBase64( strSrc.toStdString().c_str(), &binSrc );

    ret = JS_TSP_encodeRequest( &binSrc, strHash.toStdString().c_str(), strPolicy.toStdString().c_str(), 1, &binReq );
    if( ret != 0 )
    {
        manApplet->elog( QString("failed to encode request [%1]").arg( ret ));
        goto end;
    }

    ret = JS_HTTP_requestPostBin( strURL.toStdString().c_str(), "application/tsp-request", &binReq, &nStatus, &binRsp );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to request HTTP post [%1]").arg( ret ));
        goto end;
    }

    ret = JS_TSP_decodeResponse( &binRsp, &binData, &binTST );
    if( ret != 0 )
    {
        manApplet->elog( QString( "failed to decode response message [%1]").arg(ret));
        goto end;
    }

    mOutputText->setPlainText( getHexString( &binRsp ) );

end :
    JS_BIN_reset( &binSrc );
    JS_BIN_reset( &binTSPCert );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binTST );
    JS_TSP_resetTSTInfo( &sTSTInfo );
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
        manApplet->warningBox(tr( "failed to decode TSP response"), this );
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
        manApplet->warningBox(tr( "failed to decode TSP response"), this );
        goto end;
    }

    if( smgr->TSPUse() )
    {
        ret = JS_BIN_fileReadBER( smgr->TSPSrvCertPath().toLocal8Bit().toStdString().c_str(), &binCert );
        if( ret <= 0 )
        {
            manApplet->warningBox( tr( "failed to read TSP Server certificate" ), this );
            goto end;
        }
    }

    ret = JS_PKCS7_verifySignedData( &binData, &binCert, &binData );
    strVerify = QString( "Verification result value : %1" ).arg( ret );

    manApplet->messageBox( strVerify, this );

end :
    JS_BIN_reset( &binRsp );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binTST );
    JS_BIN_reset( &binCert );
}
