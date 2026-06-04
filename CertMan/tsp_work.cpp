#include "tsp_work.h"
#include <QtNetwork/QtNetwork>

#include "js_pki.h"
#include "commons.h"

TspWork::TspWork( qintptr ID, QObject *parent )
{
    this->socketDescriptor = ID;
}

void TspWork::run()
{
    qDebug() << "Thread started";

    socket = new QTcpSocket();

    if( !socket->setSocketDescriptor(this->socketDescriptor) )
    {
        elog( "setSocketDescriptor fail" );
        emit error( socket->error() );
        return;
    }

    connect( socket, SIGNAL(readyRead()), this, SLOT(readyRead()), Qt::DirectConnection );
    connect( socket, SIGNAL(disconnected()), this, SLOT(disconnected()) );

    qDebug() << socketDescriptor << " Client connected";

    exec();
}

void TspWork::readyRead()
{
    BIN binContent = {0,0};

    QByteArray Line;
    const QByteArray key = "Content-Length:";
    int nContentLength = 0;
    Line = socket->readLine();

    while( Line.length() > 0 )
    {
        log( QString( "Line: %1" ).arg( Line.data() ));

        int pos = Line.indexOf( key );
        if( pos >= 0 )
        {
            QByteArray value = Line.mid( pos + key.length(), Line.length() - pos ).trimmed();
            nContentLength = value.toLongLong();
            log( QString( "Content-Length: %1" ).arg( nContentLength ));
        }

        Line = socket->readLine();
        if( Line.length() <= 2 ) break;
    }

    QByteArray content = socket->readAll();

    log( QString( "Content Length: %1" ).arg( content.length() ));
    JS_BIN_set( &binContent, (const unsigned char *)content.data(), content.length() );

    log( QString( "Contents: %1" ).arg( getHexString(&binContent)));

    socket->write( content );
    socket->flush();
    socket->disconnectFromHost();
    socket->waitForDisconnected();

    JS_BIN_reset( &binContent );
}

void TspWork::disconnected()
{
    log( QString( QString( "Disconnected: %1" ).arg( socketDescriptor )));

    socket->deleteLater();
    exit(0);
}

void TspWork::log( const QString strLog, QColor cr )
{
    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;
    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );
    qDebug() << strMsg;
}

void TspWork::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}
