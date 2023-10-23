#include <QStringList>

#include "make_dn_dlg.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "settings_mgr.h"

MakeDNDlg::MakeDNDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
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

        QString strName = strNVList.at(0);
        QString strValue = strNVList.at(1);

        if( strName == "CN" )
        {
            mCNText->setText( strValue );
        }
    }
}

const QString MakeDNDlg::getDN()
{

}
