#include "about_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "js_gen.h"
#include "settings_mgr.h"

AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("About %1").arg(manApplet->getBrand()));
    setWindowFlags( (windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint );
    initialize();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    if( manApplet->isPRO() )
    {
        version_label_ = tr( "%1 [Version %2]").arg( "CertMan PRO").arg(STRINGIZE(CERTMAN_VERSION));
    }
    else
    {
        if( manApplet->isLicense() )
            version_label_ = tr( "%1 [Version %2]").arg(manApplet->getBrand()).arg(STRINGIZE(CERTMAN_VERSION));
        else
            version_label_ = tr( "%1 [Unlicensed Version %2]").arg(manApplet->getBrand()).arg(STRINGIZE(CERTMAN_VERSION));
    }


    mVersionLabel->setText( version_label_ );

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() )
    {
        mCheckUpdateBtn->setVisible(true);
        connect(mCheckUpdateBtn, SIGNAL(clicked()), this, SLOT(checkUpdate()));
    }
#endif

    mAboutText->setOpenExternalLinks(true);

    QString strAbout = tr("This program is a freeware tool created using open source."
            "If you do not use this for commercial purposes, you can use it freely " );
    strAbout += "<br>Copyright (C) 2022 ~ 2024 JayKim<br><br>";


    strAbout += tr("Third party software that may be contained in this application.");

    strAbout += "<br><b>OpenSSL 3.0.8</b>";
    strAbout += "<br>- https://www.openssl.org";
    strAbout += "<br>- <a href=https://github.com/openssl/openssl/blob/master/LICENSE.txt>Apache 2.0 License</a>";

#ifdef Q_OS_MACOS
    strAbout += "<br><br><b>QT 5.15.2</b>";
#else
    strAbout += "<br><br><b>QT 5.13.2</b>";
#endif
    strAbout += "<br>- https://www.qt.io";
    strAbout += "<br>- <a href=https://www.qt.io/licensing/open-source-lgpl-obligations>LGPL 3.0 License</a>";

#ifdef Q_OS_WIN
    strAbout += "<br><br><b>WinSparkle</b>";
    strAbout += "<br>- https://winsparkle.org";
    strAbout += "<br>- <a href=https://github.com/vslavik/winsparkle/blob/master/COPYING>MIT license</a>";
#endif

#ifdef Q_OS_MACOS
    strAbout += "<br><br><b>Sparkle</b>";
    strAbout += "<br>https://sparkle-project.org";
    strAbout += "<br><a href=https://github.com/sparkle-project/Sparkle/blob/2.x/LICENSE>MIT license</a>";
#endif

    QString strLibVersion = JS_GEN_getBuildInfo();

    strAbout += "<br><br>Library: ";
    strAbout += strLibVersion;

    strAbout += "<br>";
    strAbout += getBuild();
    strAbout += "<br><br>";


    /*
    strAbout += "<br><br>blog: ";
    strAbout += "<a href=https://jykim74.tistory.com>https://jykim74.tistory.com</a>";
    strAbout += "<br>mail: ";
    strAbout += "<a href=mailto:jykim74@gmail.com>jykim74@gmail.com</a>";
    */

#ifdef _AUTO_UPDATE
    mCheckUpdateBtn->show();
#else
    mCheckUpdateBtn->hide();
#endif

//    mAboutText->setText( strAbout );
    mAboutText->setHtml( strAbout );
    mCloseBtn->setDefault(true);
}

AboutDlg::~AboutDlg()
{
//    delete ui;
}

QString AboutDlg::getBuild()
{
    QString strBuild = QString( "Build Date: %1 %2").arg( __DATE__ ).arg( __TIME__ );
    return strBuild;
}

void AboutDlg::initialize()
{
    static QFont font;
    QString strFont = manApplet->settingsMgr()->getFontFamily();
    font.setFamily( strFont );
    font.setBold(true);
    font.setPointSize(15);
    mVersionLabel->setFont(font);
}

#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
