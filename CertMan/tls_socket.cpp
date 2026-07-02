#include "tls_socket.h"

TLSSocket::TLSSocket(QSslSocket *socket, QObject *parent)
    : QObject(parent),
    m_socket(socket)
{
    connect(socket,&QSslSocket::readyRead, this,&TLSSocket::onReadyRead);

    connect(socket,&QSslSocket::disconnected, this,&TLSSocket::onDisconnected);
}

void TLSSocket::onReadyRead()
{
    m_buffer += m_socket->readAll();

    processBuffer();
}

void TLSSocket::processBuffer()
{
    while (true)
    {
        if (m_state == WaitingHeader)
        {
            int pos = m_buffer.indexOf("\r\n\r\n");

            if (pos < 0)
                return;

            QByteArray header = m_buffer.left(pos);

            parseHeader(header);

            m_buffer.remove(0, pos + 4);

            if (m_contentLength == 0)
            {
                processRequest();
                continue;
            }

            m_state = WaitingBody;
        }

        if (m_state == WaitingBody)
        {
            if (m_buffer.size() < m_contentLength)
                return;

            m_body = m_buffer.left(m_contentLength);

            m_buffer.remove(0, m_contentLength);

            processRequest();
        }
    }
}

void TLSSocket::parseHeader(const QByteArray &header)
{
    m_headers.clear();
    m_contentLength = 0;

    QList<QByteArray> lines = header.split('\n');

    if(lines.isEmpty())
        return;

    QByteArray requestLine = lines.takeFirst().trimmed();

    QList<QByteArray> first = requestLine.split(' ');

    if(first.size() >= 3)
    {
        m_method = first[0];
        m_uri = first[1];
        m_version = first[2];
    }

    for(const QByteArray &line : lines)
    {
        QByteArray l = line.trimmed();

        int pos = l.indexOf(':');

        if(pos < 0)
            continue;

        QString key =
            QString::fromUtf8(l.left(pos)).trimmed();

        QString value =
            QString::fromUtf8(l.mid(pos+1)).trimmed();

        m_headers[key] = value;

        if(key.compare("Content-Length",
                        Qt::CaseInsensitive)==0)
        {
            m_contentLength = value.toInt();
        }
    }
}

void TLSSocket::processRequest()
{
    qDebug()<<"Method ="<<m_method;
    qDebug()<<"URI ="<<m_uri;
    qDebug()<<"Version ="<<m_version;

    for(auto it=m_headers.begin();
         it!=m_headers.end();
         ++it)
    {
        qDebug()<<it.key()<<":"<<it.value();
    }

    qDebug()<<"Body Size ="<<m_body.size();

    QByteArray response;

    response += "HTTP/1.1 200 OK\r\n";
    response += "Content-Type:text/plain\r\n";
    response += "Content-Length:2\r\n";
    response += "Connection:Keep-Alive\r\n";
    response += "\r\n";
    response += "OK";

    m_socket->write(response);

    //--------------------------------------------------
    // 다음 Request 준비
    //--------------------------------------------------

    m_state = WaitingHeader;

    m_contentLength = 0;

    m_headers.clear();

    m_body.clear();

    m_method.clear();
    m_uri.clear();
    m_version.clear();
}

void TLSSocket::onDisconnected()
{
    deleteLater();
}
