#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CAMan";
    const char *kSaveDBPath = "saveDBPath";
    const char *kPKCS11Use = "PKCS11Use";
    const char *kSlotID = "SlotID";
    const char *kP11LibPath = "PKCS11LibPath";
    const char *kBaseDN = "BaseDN";
    const char *kListCount = "ListCount";
    const char *kKMIPUse = "KMIPUse";
    const char *kKMIPHost = "KMIPHost";
    const char *kKMIPPort = "KMIPPort";
    const char *kKMIPCACertPath = "KMIPCACertPath";
    const char *kKMIPCertPath = "KMIPCertPath";
    const char *kKMIPPrivateKeyPath = "KMIPPrivateKeyPath";
    const char *kKMIPUserName = "KMIPUserName";
    const char *kKMIPPasswd = "KMIPPasswd";
    const char *kOCSPUse = "OCSPUse";
    const char *kOCSPURI = "OCSPURI";
    const char *kOCSPSrvCertPath = "OCSPSrvCertPath";
    const char *kOCSPAttachSign = "OCSPAttachSign";
    const char *kOCSPSignerPriPath = "OCSPSignerPriPath";
    const char *kOCSPSignerCertPath = "OCSPSignerCertPath";
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

void SettingsMgr::setBaseDN( QString strBaseDN )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kBaseDN, strBaseDN );
    settings.endGroup();
}

QString SettingsMgr::baseDN()
{
    QString strBaseDN;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strBaseDN = settings.value( kBaseDN, "").toString();
    settings.endGroup();

    return strBaseDN;
}

void SettingsMgr::setListCount( int nCount )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kListCount, nCount );
    settings.endGroup();
}

int SettingsMgr::listCount()
{
    int nCount = 0;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    nCount = settings.value( kListCount, 15 ).toInt();
    settings.endGroup();

    return nCount;
}

void SettingsMgr::setKMIPUse( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPUse, val );
    settings.endGroup();
}

bool SettingsMgr::KMIPUse()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kKMIPUse, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setKMIPHost( QString strHost )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPHost, strHost );
    settings.endGroup();
}

QString SettingsMgr::KMIPHost()
{
    QString strHost;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strHost = settings.value( kKMIPHost, "").toString();
    settings.endGroup();

    return strHost;
}

void SettingsMgr::setKMIPPort( QString strPort )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPPort, strPort );
    settings.endGroup();
}

QString SettingsMgr::KMIPPort()
{
    QString strPort;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPort = settings.value( kKMIPPort, "").toString();
    settings.endGroup();

    return strPort;
}

void SettingsMgr::setKMIPCACertPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPCACertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::KMIPCACertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kKMIPCACertPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setKMIPCertPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPCertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::KMIPCertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kKMIPCertPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setKMIPPrivateKeyPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPPrivateKeyPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::KMIPPrivateKeyPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kKMIPPrivateKeyPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setKMIPUserName( QString strName )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPUserName, strName );
    settings.endGroup();
}

QString SettingsMgr::KMIPUserName()
{
    QString strName;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strName = settings.value( kKMIPUserName, "").toString();
    settings.endGroup();

    return strName;
}

void SettingsMgr::setKMIPPasswd( QString strPasswd )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kKMIPPasswd, strPasswd );
    settings.endGroup();
}

QString SettingsMgr::KMIPPasswd()
{
    QString strPasswd;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPasswd = settings.value( kKMIPPasswd, "").toString();
    settings.endGroup();

    return strPasswd;
}

void SettingsMgr::setOCSPUse( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOCSPUse, val );
    settings.endGroup();
}

bool SettingsMgr::OCSPUse()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kOCSPUse, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setOCSPURI( QString strURI )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOCSPURI, strURI );
    settings.endGroup();
}

QString SettingsMgr::OCSPURI()
{
    QString strURI;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strURI = settings.value( kOCSPURI, "").toString();
    settings.endGroup();

    return strURI;
}

void SettingsMgr::setOCSPSrvCertPath(QString strPath)
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOCSPSrvCertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::OCSPSrvCertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kOCSPSrvCertPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setOCSPAttachSign( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOCSPAttachSign, val );
    settings.endGroup();
}

bool SettingsMgr::OCSPAttachSign()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kOCSPAttachSign, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setOCSPSignerPriPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOCSPSignerPriPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::OCSPSignerPriPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kOCSPSignerPriPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setOCSPSignerCertPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kOCSPSignerCertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::OCSPSignerCertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kOCSPSignerCertPath, "").toString();
    settings.endGroup();

    return strPath;
}
