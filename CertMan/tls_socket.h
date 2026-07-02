#ifndef TLSSOCKET_H
#define TLSSOCKET_H

#include <QObject>
#include <QSslSocket>
#include <QMap>

class TLSSocket : public QObject
{
    Q_OBJECT

public:
    explicit TLSSocket( QSslSocket *socket, QObject *parent = nullptr );

private slots:
    void onReadyRead();
    void onDisconnected();

private:

    enum State
    {
        WaitingHeader,
        WaitingBody
    };

    void processBuffer();
    void parseHeader(const QByteArray &header);
    void processRequest();

    QSslSocket *m_socket;

    QByteArray m_buffer;

    State m_state = WaitingHeader;

    int m_contentLength = 0;

    QString m_method;
    QString m_uri;
    QString m_version;

    QMap<QString, QString> m_headers;

    QByteArray m_body;
};

#endif // TLSSOCKET_H
