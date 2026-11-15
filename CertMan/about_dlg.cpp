/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "about_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "js_gen.h"
#include "settings_mgr.h"
#include "copy_right_dlg.h"

AboutDlg::AboutDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);
    setWindowTitle(tr("About %1").arg(manApplet->getBrand()));
    setWindowFlags( (windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowStaysOnTopHint );
    initialize();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mCopyRightText, SIGNAL(anchorClicked(QUrl)), this, SLOT(anchorClick(QUrl)));

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
    mCopyRightText->setOpenExternalLinks(true);

    showInfo();
    showCopyright();

#ifdef _AUTO_UPDATE
    mCheckUpdateBtn->show();
#else
    mCheckUpdateBtn->hide();
#endif

    mCloseBtn->setDefault(true);

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
    mCopyTab->layout()->setSpacing(5);
    mCopyTab->layout()->setMargin(5);
    mOpenTab->layout()->setSpacing(5);
    mOpenTab->layout()->setMargin(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
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

    tabWidget->setCurrentIndex(0);
}

void AboutDlg::anchorClick( const QUrl& url )
{
    CopyRightDlg copyRight;
    copyRight.setURL( url );
    copyRight.exec();

    mCopyRightText->clear();
    showInfo();
    return;
}

QString AboutDlg::readLicenseText()
{
    QFile file(":/LICENSE");

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    return QString::fromUtf8(file.readAll());
}

void AboutDlg::showInfo()
{
    QString strAbout = readLicenseText();
    QString strLibVersion = JS_GEN_getBuildInfo();

    strAbout += "\n\nJKLab PKI Library: ";
    strAbout += strLibVersion;
    strAbout += "\n";
    strAbout += manApplet->getBrand();
    strAbout += " : ";
    strAbout += getBuild();

//    mAboutText->setHtml( strAbout );
    mAboutText->setText( strAbout );
}

void AboutDlg::showCopyright()
{
    QString strCopyRight;

    strCopyRight = tr("Third party software that may be contained in this application.");

    strCopyRight += QString( "<br><br><b>%1</b>" ).arg( JS_GEN_openSSLVersion());
    strCopyRight += "<br>- https://www.openssl.org";
    strCopyRight += "<br>- <a href=https://github.com/openssl/openssl/blob/master/LICENSE.txt>Apache 2.0 License</a>";

    strCopyRight += "<br><br><b>QT 5.15.2</b>";

    strCopyRight += "<br>- https://www.qt.io";
    strCopyRight += "<br>- <a href=https://www.qt.io/licensing/open-source-lgpl-obligations>LGPL 3.0 License</a>";

    strCopyRight += "<br><br><b>OpenLDAP</b>";
    strCopyRight += "<br>- https://www.openldap.org";
    strCopyRight += "<br>- <a href=https://www.openldap.org/doc/admin20/license.html>The OpenLDAP Public License</a>";

    strCopyRight += "<br><br><b>ltdl</b>";
    strCopyRight += "<br>- https://www.gnu.org/software/libtool";
    strCopyRight += "<br>- <a href=https://www.gnu.org/licenses/lgpl-3.0.en.html>LGPL 3.0 Licese</a>";

#ifdef Q_OS_WIN
    strCopyRight += "<br><br><b>WinSparkle</b>";
    strCopyRight += "<br>- https://winsparkle.org";
    strCopyRight += "<br>- <a href=https://github.com/vslavik/winsparkle/blob/master/COPYING>MIT license</a>";
#endif

#ifdef Q_OS_MACOS
    strCopyRight += "<br><br><b>Sparkle</b>";
    strCopyRight += "<br>- https://sparkle-project.org";
    strCopyRight += "<br>- <a href=https://github.com/sparkle-project/Sparkle/blob/2.x/LICENSE>MIT license</a>";
#endif

    strCopyRight += "<br><br><b>jsmn</b>";
    strCopyRight += "<br>- https://zserge.com/jsmn";
    strCopyRight += "<br>- <a href=https://github.com/zserge/jsmn/blob/master/LICENSE>MIT License</a>";

/*
    strCopyRight += "<br><br><b>shamir-secret</b>";
    strCopyRight += "<br>- https://github.com/KPN-CISO/shamir-secret";
    strCopyRight += "<br>- <a href=https://github.com/KPN-CISO/shamir-secret/blob/master/LICENSE>MIT License</a>";
*/

    strCopyRight += "<br><br><b>sscep</b>";
    strCopyRight += "<br>- https://github.com/certnanny/sscep";
    strCopyRight += "<br>- <a href=https://github.com/certnanny/sscep/blob/master/COPYING>OpenSSL License</a>";


    strCopyRight += "<br><br><b>OpenKMIP</b>";
    strCopyRight += "<br>- https://github.com/OpenKMIP/libkmip";
    strCopyRight += "<br>- <a href=https://github.com/OpenKMIP/libkmip/blob/master/LICENSE>Apache 2.0 License</a>";

    mCopyRightText->setText( strCopyRight );
}

#ifdef _AUTO_UPDATE
void AboutDlg::checkUpdate()
{
    AutoUpdateService::instance()->checkUpdate();
    close();
}
#endif
