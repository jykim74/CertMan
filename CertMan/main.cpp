/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "man_applet.h"
#include "i18n_helper.h"
#include "settings_mgr.h"

#if defined(QT_DEBUG)
int g_nVerbose = 1;
#else
int g_nVerbose = 0;
#endif


int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "CertMan" );

    QGuiApplication::setWindowIcon(QIcon(":/images/certman.png"));

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName() );
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "The file to open" );
    parser.process(app);

    I18NHelper::getInstance()->init();

    ManApplet mApplet;
    manApplet = &mApplet;
    manApplet->start();

    QFont font;
    QString strFont = manApplet->settingsMgr()->getFontFamily();

    font.setFamily( strFont );
    app.setFont(font);

    MainWindow *mw = manApplet->mainWindow();
    if( !parser.positionalArguments().isEmpty() )
    {
        mw->loadDB( parser.positionalArguments().first() );
        mw->show();
    }

    return app.exec();
}
