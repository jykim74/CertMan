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

    void setKMIPUse( bool val );
    bool KMIPUse();

    void setKMIPHost( QString strHost );
    QString KMIPHost();

    void setKMIPPort( QString strPort );
    QString KMIPPort();

    void setKMIPCACertPath( QString strPath );
    QString KMIPCACertPath();

    void setKMIPCertPath( QString strPath );
    QString KMIPCertPath();

    void setKMIPPrivateKeyPath( QString strPath );
    QString KMIPPrivateKeyPath();

    void setKMIPUserName( QString strName );
    QString KMIPUserName();

    void setKMIPPasswd( QString strPasswd );
    QString KMIPPasswd();

    void loadSettings();

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
