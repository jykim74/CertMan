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

    void setPKCS11Use( bool val );
    bool PKCS11Use();

    void setSlotID( int nID );
    int slotID();

    void setPKCS11LibraryPath( QString strLibPath );
    QString PKCS11LibraryPath();

    void setBaseDN( QString strBaseDN );
    QString baseDN();

    void setListCount( int nCount );
    int listCount();

    void loadSettings();

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
