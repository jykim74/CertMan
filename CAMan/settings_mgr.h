#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT

public:
    SettingsMgr( QObject *parent = nullptr );

    void setSaveDBPath( bool val );
    bool saveDBPath();

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
