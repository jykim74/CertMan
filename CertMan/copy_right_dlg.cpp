/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QFile>
#include <QTextStream>

#include "copy_right_dlg.h"

CopyRightDlg::CopyRightDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
}

CopyRightDlg::~CopyRightDlg()
{

}

void CopyRightDlg::setURL( const QUrl& url )
{
    QString strPath = QCoreApplication::applicationDirPath();
    strPath += "/";
    strPath += url.path();

    QFile file( strPath );
    file.open( QFile::ReadOnly|QFile::Text);

    QTextStream openFile( &file );
    QString strTxt = openFile.readAll();
    file.close();

    mLicenseText->setPlainText( strTxt );
}
