#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>

class MainWindow;

class ManApplet : public QObject
{
    Q_OBJECT
public:
    explicit ManApplet(QObject *parent = nullptr);
    void start();

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
