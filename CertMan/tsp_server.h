#ifndef TSP_SERVER_H
#define TSP_SERVER_H

#include <QtCore/QObject>
#include <QtNetwork/QTcpServer>
#include <QPlainTextEdit>


class TSPServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit TSPServer( QObject *parent = nullptr );
    void startServer( int nPort );
    void setLogEdit( QPlainTextEdit *pEdit );

public slots:

private:
    QPlainTextEdit* log_edit_;

protected:
    void incomingConnection( qintptr socketDescriptor );

    void log( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );
    void elog( const QString strLog );
};

#endif // TSP_SERVER_H
