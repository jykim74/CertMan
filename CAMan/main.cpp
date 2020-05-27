#include "mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include "man_applet.h"
#include "i18n_helper.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "CAMan" );

    QFile qss(":/caman.qss");
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

    /*
    MainWindow w;
    w.show();
    */

    return app.exec();
}
