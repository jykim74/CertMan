#include "work_thread.h"
#include <QtNetwork/QtNetwork>

WorkThread::WorkThread( qintptr ID, QObject *parent )
{
    this->socketDescriptor = ID;
}

void WorkThread::run()
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

void WorkThread::setLogEdit( QPlainTextEdit *pEdit )
{
    log_edit_ = pEdit;
}

void WorkThread::readyRead()
{
    QByteArray Data = socket->readAll();

    log( QString( "Data size: %1" ).arg( Data.size() ));

    QString strData = Data.data();

    qDebug() << socketDescriptor << " Data in: " << strData;

    socket->write( Data );
    socket->flush();
    socket->disconnectFromHost();
    socket->waitForDisconnected();
}

void WorkThread::disconnected()
{
    log( QString( QString( "Disconnected: %1" ).arg( socketDescriptor )));

    socket->deleteLater();
    exit(0);
}

void WorkThread::log( const QString strLog, QColor cr )
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

void WorkThread::elog( const QString strLog )
{
    log( strLog, QColor(0xFF,0x00,0x00));
}
