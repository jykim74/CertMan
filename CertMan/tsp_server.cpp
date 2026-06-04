#include <QDebug>
#include <QtNetwork/QtNetwork>

#include "tsp_server.h"
#include "tsp_work.h"
#include "man_applet.h"

TSPServer::TSPServer( QObject *parent ) :
    QTcpServer(parent)
{
    log_edit_ = nullptr;
}

void TSPServer::setLogEdit( QPlainTextEdit *pEdit )
{
    log_edit_ = pEdit;
}

void TSPServer::startServer( int nPort )
{
    if( !this->listen( QHostAddress::Any, nPort ) )
    {
        log( "Could not start server" );
    }
    else
    {
        log( QString( "Listening to port: %1" ).arg( nPort ) );
    }
}

void TSPServer::incomingConnection( qintptr socketDescriptor )
{
    log( "Connecting..." );

    TspWork *thread = new TspWork( socketDescriptor, this );

    connect( thread, SIGNAL(finished()), thread, SLOT(deleteLater()) );

    thread->start();
}

void TSPServer::log( const QString strLog, QColor cr )
{
    QDateTime date;
    date.setTime_t( time(NULL));
    QString strMsg;
    strMsg = QString( "[%1] %2\n" ).arg( date.toString("HH:mm:ss") ).arg( strLog );

    if( log_edit_ )
    {
        QTextCursor cursor = log_edit_->textCursor();

        QTextCharFormat format;
        format.setForeground( cr );
        cursor.mergeCharFormat(format);


        cursor.insertText( strMsg );

        log_edit_->setTextCursor( cursor );
        log_edit_->repaint();
    }
    else
    {
        qDebug() << strMsg;
    }
}

void TSPServer::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}
