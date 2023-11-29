#include <QSettings>

#include "settings_mgr.h"

namespace  {
    const char *kBehaviorGroup = "CertMan";
    const char *kSaveRemoteInfo = "saveRemoteInfo";
    const char *kRemoteInfo = "remoteInfo";
    const char *kServerStatus = "serverStatus";
    const char *kUseLogTab = "useLogTab";
    const char *kPKCS11Use = "PKCS11Use";
    const char *kSlotIndex = "SlotIndex";
    const char *kP11LibPath = "PKCS11LibPath";
    const char *kP11Pin = "PKCS11Pin";
    const char *kLDAPHost = "LDAPHost";
    const char *kLDAPPort = "LDAPPort";
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
    const char *kREGUse = "REGUse";
    const char *kREGURI = "REGURI";
    const char *kCMPUse = "CMPUse";
    const char *kCMPURI = "CMPURI";
    const char *kCMPRootCACertPath = "CMPRootCACertPath";
    const char *kCMPCACertPath = "CMPCACertPath";
    const char *kTSPUse = "TSPUse";
    const char *kTSPURI = "TSPURI";
    const char *kTSPSrvCertPath = "TSPSrvCertPath";
    const char *kSCEPUse = "SCEPUse";
    const char *kSCEPURI = "SCEPURI";
    const char *kSCEPMutualAuth = "SCEPMutualAuth";
    const char *kSCEPPriPath = "SCEPPriPath";
    const char *kSCEPCertPath = "SCEPCertPath";
    const char *kDefaultHash = "defaultHash";
    const char *kDefaultECCParam = "defaultECCParam";
    const char *kFontFamily = "fontFamily";
    const char *kMisc = "Misc";
    const char *kEmail = "email";
    const char *kLicense = "license";
    const char *kCertProfileNum = "certProfileNum";
    const char *kCRLProfileNum = "CRLProfileNum";
    const char *kIssuerNum = "issuerNum";
}

SettingsMgr::SettingsMgr( QObject *parent ) : QObject (parent)
{
    cert_profile_num_ = 0;
    crl_profile_num_ = 0;
    issuer_num_ = 0;

    loadSettings();
}

void SettingsMgr::loadSettings()
{
    QSettings settings;

    settings.beginGroup(kBehaviorGroup);
    settings.endGroup();

    getDefaultHash();
    getDefaultECCParam();

    getCertProfileNum();
    getCRLProfileNum();
}

void SettingsMgr::setSaveRemoteInfo( bool val )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSaveRemoteInfo, val );
    settings.endGroup();
}

bool SettingsMgr::saveRemoteInfo()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kSaveRemoteInfo, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setRemoteInfo( QString strRemoteInfo )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kRemoteInfo, strRemoteInfo );
    settings.endGroup();
}

QString SettingsMgr::remoteInfo()
{
    QString strInfo;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strInfo = settings.value( kRemoteInfo, "" ).toString();
    settings.endGroup();

    return strInfo;
}

void SettingsMgr::setServerStatus( bool val )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kServerStatus, val );
    settings.endGroup();
}

bool SettingsMgr::serverStatus()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kServerStatus, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setUseLogTab( bool bVal )
{
    QSettings settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kUseLogTab, bVal );
    settings.endGroup();
}

bool SettingsMgr::getUseLogTab()
{
    QSettings settings;

    bool val;

    settings.beginGroup(kBehaviorGroup);
    val = settings.value( kUseLogTab, false).toBool();
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

void SettingsMgr::setSlotIndex(int nIndex)
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSlotIndex, nIndex );
    settings.endGroup();
}

int SettingsMgr::slotIndex()
{
    int nIndex = -1;

    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    nIndex = settings.value( kSlotIndex, 0 ).toInt();
    settings.endGroup();

    return nIndex;
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

void SettingsMgr::setPKCS11Pin( QString strPin )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kP11Pin, strPin );
    settings.endGroup();
}

QString SettingsMgr::PKCS11Pin()
{
    QString strPin;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPin = settings.value( kP11Pin, "" ).toString();
    settings.endGroup();

    return strPin;
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

void SettingsMgr::setLDAPHost( QString strHost )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kLDAPHost, strHost );
    settings.endGroup();
}

QString SettingsMgr::LDAPHost()
{
    QString strHost;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strHost = settings.value( kLDAPHost, "localhost").toString();
    settings.endGroup();

    return strHost;
}

void SettingsMgr::setLDAPPort( int nPort )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kLDAPPort, nPort );
    settings.endGroup();
}

int SettingsMgr::LDAPPort()
{
    int nPort = 0;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    nPort = settings.value( kLDAPPort, 389 ).toInt();
    settings.endGroup();

    return nPort;
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

void SettingsMgr::setREGUse( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kREGUse, val );
    settings.endGroup();
}

bool SettingsMgr::REGUse()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kREGUse, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setREGURI( QString strURI )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kREGURI, strURI );
    settings.endGroup();
}

QString SettingsMgr::REGURI()
{
    QString strURI;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strURI = settings.value( kREGURI, "").toString();
    settings.endGroup();

    return strURI;
}

void SettingsMgr::setCMPUse( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kCMPUse, val );
    settings.endGroup();
}

bool SettingsMgr::CMPUse()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kCMPUse, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setCMPURI( QString strURI )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kCMPURI, strURI );
    settings.endGroup();
}

QString SettingsMgr::CMPURI()
{
    QString strURI;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strURI = settings.value( kCMPURI, "").toString();
    settings.endGroup();

    return strURI;
}

void SettingsMgr::setCMPRootCACertPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kCMPRootCACertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::CMPRootCACertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kCMPRootCACertPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setCMPCACertPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kCMPCACertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::CMPCACertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kCMPCACertPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setTSPUse( bool val )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kTSPUse, val );
    settings.endGroup();
}

bool SettingsMgr::TSPUse()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kTSPUse, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setTSPURI( QString strURI )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kTSPURI, strURI );
    settings.endGroup();
}

QString SettingsMgr::TSPURI()
{
    QString strURI;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strURI = settings.value( kTSPURI, "").toString();
    settings.endGroup();

    return strURI;
}

void SettingsMgr::setTSPSrvCertPath(QString strPath)
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kTSPSrvCertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::TSPSrvCertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kTSPSrvCertPath, "").toString();
    settings.endGroup();

    return strPath;
}


void SettingsMgr::setSCEPUse( bool val )
{
    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSCEPUse, val );
    settings.endGroup();
}

bool SettingsMgr::SCEPUse()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kSCEPUse, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setSCEPURI( QString strURI )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSCEPURI, strURI );
    settings.endGroup();
}

QString SettingsMgr::SCEPURI()
{
    QString strURI;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strURI = settings.value( kSCEPURI, "").toString();
    settings.endGroup();

    return strURI;
}

void SettingsMgr::setSCEPMutualAuth( bool val )
{
    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSCEPMutualAuth, val );
    settings.endGroup();
}

bool SettingsMgr::SCEPMutualAuth()
{
    QSettings   settings;

    bool val;

    settings.beginGroup( kBehaviorGroup );
    val = settings.value( kSCEPMutualAuth, false ).toBool();
    settings.endGroup();

    return val;
}

void SettingsMgr::setSCEPPriKeyPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSCEPPriPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::SCEPPriKeyPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kSCEPPriPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setSCEPCertPath( QString strPath )
{
    QSettings   settings;

    settings.beginGroup( kBehaviorGroup );
    settings.setValue( kSCEPCertPath, strPath );
    settings.endGroup();
}

QString SettingsMgr::SCEPCertPath()
{
    QString strPath;

    QSettings   settings;
    settings.beginGroup( kBehaviorGroup );
    strPath = settings.value( kSCEPCertPath, "").toString();
    settings.endGroup();

    return strPath;
}

void SettingsMgr::setDefaultHash( const QString& strHash )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kDefaultHash, strHash );
    sets.endGroup();

    default_hash_ = strHash;
}

QString SettingsMgr::getDefaultHash()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    default_hash_ = sets.value( kDefaultHash, "SHA256" ).toString();
    sets.endGroup();

    return default_hash_;
}


void SettingsMgr::setDefaultECCParam( const QString& strECCParam )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kDefaultECCParam, strECCParam );
    sets.endGroup();

    default_ecc_param_ = strECCParam;
}

QString SettingsMgr::getDefaultECCParam()
{
    QSettings sets;

    sets.beginGroup( kBehaviorGroup );
    default_ecc_param_ = sets.value( kDefaultECCParam, "prime256v1" ).toString();
    sets.endGroup();

    return default_ecc_param_;
}

void SettingsMgr::setFontFamily( const QString& strFamily )
{
    QSettings sets;
    sets.beginGroup( kBehaviorGroup );
    sets.setValue( kFontFamily, strFamily );
    sets.endGroup();
}

QString SettingsMgr::getFontFamily()
{
    QSettings sets;

#ifdef Q_OS_MAC
    QString strDefault = "Monaco";
#else
#ifdef Q_OS_LINUX
    QString strDefault = "Monospace";
#else
    QString strDefault = "Consolas";
#endif
#endif

    sets.beginGroup( kBehaviorGroup );
    QString strFamily = sets.value( kFontFamily, strDefault ).toString();
    sets.endGroup();

    return strFamily;
}

void SettingsMgr::setEmail( const QString strEmail )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kEmail, strEmail );
    sets.endGroup();
}

QString SettingsMgr::getEmail()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    QString strEmail = sets.value( kEmail, "" ).toString();
    sets.endGroup();

    return strEmail;
}

void SettingsMgr::setLicense( const QString strLicense )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kLicense, strLicense );
    sets.endGroup();
}

QString SettingsMgr::getLicense()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    QString strLicense = sets.value( kLicense, "" ).toString();
    sets.endGroup();

    return strLicense;
}


void SettingsMgr::setCertProfileNum( int num )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kCertProfileNum, num );
    sets.endGroup();

    cert_profile_num_ = num;
}

int SettingsMgr::getCertProfileNum()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    cert_profile_num_ = sets.value( kCertProfileNum, 0 ).toInt();
    sets.endGroup();

    return cert_profile_num_;
}

void SettingsMgr::setCRLProfileNum( int num )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kCRLProfileNum, num );
    sets.endGroup();

    crl_profile_num_ = num;
}

int SettingsMgr::getCRLProfileNum()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    crl_profile_num_ = sets.value( kCRLProfileNum, 0 ).toInt();
    sets.endGroup();

    return crl_profile_num_;
}

void SettingsMgr::setIssuerNum( int num )
{
    QSettings sets;
    sets.beginGroup( kMisc );
    sets.setValue( kIssuerNum, num );
    sets.endGroup();

    issuer_num_ = num;
}

int SettingsMgr::getIssuerNum()
{
    QSettings sets;

    sets.beginGroup( kMisc );
    issuer_num_ = sets.value( kIssuerNum, 0 ).toInt();
    sets.endGroup();

    return issuer_num_;
}
