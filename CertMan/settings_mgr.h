/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>


class SettingsMgr : public QObject
{
    Q_OBJECT

public:
    SettingsMgr( QObject *parent = nullptr );
    void removeSet( const QString& group, const QString& name );

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

    void setREGAdminName( const QString strName );
    QString REGAdminName();
    void setREGPassword( const QString strPassword );
    QString REGPassword();

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

    void setStopMessage( const time_t tLastTime );
    time_t getStopMessage();

    void setCertProfileNum( int num );
    int getCertProfileNum();
    int certProfileNum() { return cert_profile_num_; };

    void setCRLProfileNum( int num );
    int getCRLProfileNum();
    int CRLProfileNum() { return crl_profile_num_; };

    void setIssuerNum( int num );
    int getIssuerNum();
    int issuerNum() { return issuer_num_; };

    void setHexAreaWidth( int width );
    int getHexAreaWidth();
    int hexAreaWidth() { return hex_area_width_; };

    void loadSettings();

    int viewValue( int nType );
    int getViewValue( int nType );
    void setViewValue( int nVal );
    void clearViewValue( int nType );

    void setRunTime( time_t tRun );
    time_t getRunTime();

    void setShowPriInfo( bool bVal );
    bool getShowPriInfo();
    bool showPriInfo() { return show_pri_info_; };

private:
    QString default_hash_;
    QString default_ecc_param_;
    int cert_profile_num_;
    int crl_profile_num_;
    int issuer_num_;
    int hex_area_width_;
    bool show_pri_info_;

    int view_file_;
    int view_tool_;
    int view_data_;
    int view_server_;
    int view_help_;
private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
