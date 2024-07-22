/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QStringList>

#include "make_dn_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "settings_mgr.h"

MakeDNDlg::MakeDNDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    mOKBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MakeDNDlg::~MakeDNDlg()
{

}

void MakeDNDlg::setDN( const QString strDN )
{
    QStringList strList = strDN.split( "," );

    for( int i = 0; i < strList.size(); i++ )
    {
        QString strPart = strList.at(i);
        QStringList strNVList = strPart.split( "=" );
        if( strNVList.size() != 2 ) continue;

        QString strName = strNVList.at(0).toUpper();
        QString strValue = strNVList.at(1);

        if( strName == "CN" )
            mCNText->setText( strValue );
        else if( strName == "EMAILADDRESS" )
            mEmailAddressText->setText( strValue );
        else if( strName == "O" )
            mOText->setText( strValue );
        else if( strName == "OU" )
            mOUText->setText( strValue );
        else if( strName == "L" )
            mLText->setText( strValue );
        else if( strName == "ST" )
            mSTText->setText( strValue );
        else if( strName == "C" )
            mCText->setText( strValue );
    }
}

const QString MakeDNDlg::getDN()
{
    QString strEmailAddress = mEmailAddressText->text();
    QString strCN = mCNText->text();
    QString strO = mOText->text();
    QString strOU = mOUText->text();
    QString strL = mLText->text();
    QString strST = mSTText->text();
    QString strC = mCText->text();

    QString strDN;

    if( strEmailAddress.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "emailAddress=%1").arg(strEmailAddress);
    }

    if( strCN.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "CN=%1").arg( strCN );
    }

    if( strO.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "O=%1").arg( strO );
    }

    if( strOU.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "OU=%1").arg( strOU );
    }

    if( strL.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "L=%1").arg( strL );
    }

    if( strST.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "ST=%1").arg( strST );
    }

    if( strC.length() > 0 )
    {
        if( strDN.length() > 0 ) strDN += ",";
        strDN += QString( "C=%1" ).arg( strC );
    }

    return strDN;
}

void MakeDNDlg::clickOK()
{
    QString strDN = getDN();

    if( strDN.length() < 3 )
    {
        manApplet->warningBox( tr( "Enter DN value" ), this );
        mCNText->setFocus();
        return;
    }

    accept();
}

void MakeDNDlg::clickClear()
{
    mEmailAddressText->clear();
    mCNText->clear();
    mOText->clear();
    mOUText->clear();
    mSTText->clear();
    mCText->clear();
    mLText->clear();

}
