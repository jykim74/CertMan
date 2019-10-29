#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CAMan";
    const char *kSaveDBPath = "saveDBPath";
}

SettingsMgr::SettingsMgr( QObject *parent ) : QObject (parent)
{

}

void SettingsMgr::setSaveDBPath( bool val )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSaveDBPath, val );
    settings.endGroup();
}

bool SettingsMgr::saveDBPath()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kSaveDBPath, false ).toBool();
    settings.endGroup();

    return val;
}
