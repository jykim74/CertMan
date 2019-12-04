#include "about_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"


AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("About %1").arg(manApplet->getBrand()));
    setWindowFlags( (windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint );

    version_label_ = tr( "About %1 (%2)").arg( "CAMan").arg(STRINGIZE(CAMAN_VERSION));
    mVersionLabel->setText( version_label_ );

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() )
    {
        mCheckUpdateBtn->setVisible(true);
        connect(mCheckUpdateBtn, SIGNAL(clicked()), this, SLOT(checkUpdate()));
    }
#endif

    QString strAbout = tr("This is freeware tool to decode ASN.1 and BER "
            "If you do not use this for commercial purposes, "
            "you can use it freely "
            "If you have any opinions on this tool, please send me a mail"
            "\r\n\r\nCopyright (C) 2019 ~ 2020 JongYeob Kim\r\n"
            "mailto : jykim74@gmail.com");

    mAboutText->setText( strAbout );
}

AboutDlg::~AboutDlg()
{
//    delete ui;
}


#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
