#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CAMan";
    const char *kSaveDBPath = "saveDBPath";
    const char *kPKCS11Use = "PKCS11Use";
    const char *kSlotID = "SlotID";
    const char *kP11LibPath = "PKCS11LibPath";
}

SettingsMgr::SettingsMgr( QObject *parent ) : QObject (parent)
{
    loadSettings();
}

void SettingsMgr::loadSettings()
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    settings.endGroup();
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

void SettingsMgr::setPKCS11Use( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kPKCS11Use, val );
    settings.endGroup();
}

bool SettingsMgr::PKCS11Use()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kPKCS11Use, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setSlotID( int nID )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSlotID, nID );
    settings.endGroup();
}

int SettingsMgr::slotID()
{
    int nID = -1;

    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    nID = settings.value( kSlotID, -1 ).toInt();
    settings.endGroup();

    return nID;
}

void SettingsMgr::setPKCS11LibraryPath( QString strLibPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kP11LibPath, strLibPath );
    settings.endGroup();
}

QString SettingsMgr::PKCS11LibraryPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kP11LibPath, "" ).toString();
    settings.endGroup();

    return strPath;
}
