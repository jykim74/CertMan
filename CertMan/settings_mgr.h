/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef SETTINGS_MGR_H
#define SETTINGS_MGR_H

#include <QObject>

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
const char *kSetListCount = "ListCount";
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
const char *kREGAdminName = "REGAdminName";
const char *kREGPassword = "REGPassword";
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
const char *kEmail = "email";
const char *kLicense = "license";
const char *kStopMessage = "stopMessage";
const char *kCertProfileNum = "certProfileNum";
const char *kCRLProfileNum = "CRLProfileNum";
const char *kIssuerNum = "issuerNum";
const char *kHexAreaWidth = "hexAreaWidth";
const char *kViewFile = "viewFile";
const char *kViewTool = "viewTool";
const char *kViewData = "viewData";
const char *kViewServer = "viewServer";
const char *kViewHelp = "viewHelp";
const char *kRunTime = "runTime";
const char *kShowPriInfo = "showPriInfo";
const char *kKeyTypeParam = "keyTypeParam";
const char *kPriEncMethod = "priEncMethod";
}


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

    void setKeyTypeParam( const QString strKeyTypeParam );
    const QString getKeyTypeParam();
    const QString keyTypeParam() { return key_type_param_; };

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

    void setPriEncMethod( const QString strMethod );
    QString getPriEncMethod();
    QString priEncMethod() { return pri_enc_method_; };

private:
    QString default_hash_;
    QString default_ecc_param_;
    int cert_profile_num_;
    int crl_profile_num_;
    int issuer_num_;
    int hex_area_width_;
    bool show_pri_info_;
    QString key_type_param_;
    QString pri_enc_method_;

    int view_file_;
    int view_tool_;
    int view_data_;
    int view_server_;
    int view_help_;
private:
    Q_DISABLE_COPY(SettingsMgr)
};

#endif // SETTINGS_MGR_H
