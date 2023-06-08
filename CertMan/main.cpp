#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "man_applet.h"
#include "i18n_helper.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "CertMan" );

    QFile qss(":/certman.qss");
    qss.open( QFile::ReadOnly );
    app.setStyleSheet(qss.readAll());

    QCommandLineParser parser;
    parser.setApplicationDescription( QCoreApplication::applicationName() );
    parser.addHelpOption();
    parser.addPositionalArgument( "file", "The file to open" );
    parser.process(app);

    I18NHelper::getInstance()->init();

    ManApplet mApplet;
    manApplet = &mApplet;
    manApplet->start();

    MainWindow *mw = manApplet->mainWindow();
    if( !parser.positionalArguments().isEmpty() )
    {
        mw->loadDB( parser.positionalArguments().first() );
        mw->show();
    }

    return app.exec();
}
