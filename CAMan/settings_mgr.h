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

    void setServerStatus( bool val );
    bool serverStatus();

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

    void setOCSPUse( bool val );
    bool OCSPUse();

    void setOCSPURI( QString strURI );
    QString OCSPURI();
    void setOCSPSrvCertPath( QString strPath );
    QString OCSPSrvCertPath();

    void setOCSPAttachSign( bool val );
    bool OCSPAttachSign();

    void setOCSPSignerPriPath( QString strPath );
    QString OCSPSignerPriPath();

    void setOCSPSignerCertPath( QString strPath );
    QString OCSPSignerCertPath();

    void setREGUse( bool val );
    bool REGUse();

    void setREGURI( QString strURI );
    QString REGURI();

    void setCMPUse( bool val );
    bool CMPUse();

    void setCMPURI( QString strURI );
    QString CMPURI();

    void setCMPRootCACertPath( QString strPath );
    QString CMPRootCACertPath();
    void setCMPCACertPath( QString strPath );
    QString CMPCACertPath();

    void setTSPUse( bool val );
    bool TSPUse();

    void setTSPURI( QString strURI );
    QString TSPURI();

    void setTSPSrvCertPath( QString strPath );
    QString TSPSrvCertPath();


    void loadSettings();

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
