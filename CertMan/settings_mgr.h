#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

class SettingsMgr : public QObject
{
    Q_OBJECT

public:
    SettingsMgr( QObject *parent = nullptr );

    void setSaveRemoteInfo( bool val );
    bool saveRemoteInfo();

    void setRemoteInfo( QString strRemoteInfo );
    QString remoteInfo();

    void setServerStatus( bool val );
    bool serverStatus();

    void setUseLogTab( bool bVal );
    bool getUseLogTab();

    void setPKCS11Use( bool val );
    bool PKCS11Use();

    void setSlotIndex( int nIndex );
    int slotIndex();

    void setPKCS11LibraryPath( QString strLibPath );
    QString PKCS11LibraryPath();

    void setPKCS11Pin( QString strPin );
    QString PKCS11Pin();

    void setBaseDN( QString strBaseDN );
    QString baseDN();

    void setLDAPHost( QString strHost );
    QString LDAPHost();

    void setLDAPPort( int nPort );
    int LDAPPort();

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


    void setSCEPUse( bool val );
    bool SCEPUse();
    void setSCEPURI( QString strURI );
    QString SCEPURI();
    void setSCEPMutualAuth( bool val );
    bool SCEPMutualAuth();
    void setSCEPPriKeyPath( QString strPath );
    QString SCEPPriKeyPath();
    void setSCEPCertPath( QString strPath );
    QString SCEPCertPath();

    void setDefaultHash( const QString& strHash );
    QString getDefaultHash();
    QString defaultHash() { return default_hash_; };

    void setDefaultECCParam( const QString& strECCParam );
    QString getDefaultECCParam();
    QString defaultECCParam() { return default_ecc_param_; };

    void setFontFamily( const QString& strFamily );
    QString getFontFamily();

    void setEmail( const QString strEmail );
    QString getEmail();

    void setLicense( const QString strLicense );
    QString getLicense();

    void setCertProfileNum( int num );
    int getCertProfileNum();
    int certProfileNum() { return cert_profile_num_; };

    void setCRLProfileNum( int num );
    int getCRLProfileNum();
    int CRLProfileNum() { return crl_profile_num_; };

    void setIssuerNum( int num );
    int getIssuerNum();
    int issuerNum() { return issuer_num_; };

    void loadSettings();

private:
    QString default_hash_;
    QString default_ecc_param_;
    int cert_profile_num_;
    int crl_profile_num_;
    int issuer_num_;

private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
