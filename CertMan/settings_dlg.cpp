/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QtGlobal>
#include <QtWidgets>

#include "i18n_helper.h"
#include "settings_dlg.h"
#include "ui_settings_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "commons.h"

const QStringList kListCountList = { "10", "15", "20", "25", "30" };

SettingsDlg::SettingsDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mLangCombo->addItems(I18NHelper::getInstance()->getLanguages());

    connect( mRestoreDefautsBtn, SIGNAL(clicked()), this, SLOT(clickRestoreDefaults()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(clickCancel()));

    connect( mP11FindBtn, SIGNAL(clicked()), this, SLOT(findP11Path()));
    connect( mUseKMIPCheck, SIGNAL(clicked()), this, SLOT(checkKMIPUse()));

    connect( mKMIPCACertFindBtn, SIGNAL(clicked()), this, SLOT(findCACert()));
    connect( mKMIPCertFindBtn, SIGNAL(clicked()), this, SLOT(findCert()));
    connect( mKMIPPrivateKeyFindBtn, SIGNAL(clicked()), this, SLOT(findPrivateKey()));

    connect( mUseOCSPCheck, SIGNAL(clicked()), this, SLOT(checkOCSPUse()));
    connect( mOCSPSrvCertFindBtn, SIGNAL(clicked()), this, SLOT(findOCSPSrvCert()));
    connect( mOCSPAttachSignCheck, SIGNAL(clicked()), this, SLOT(checkOCSPAttachSign()));
    connect( mOCSPSignerPriFindBtn, SIGNAL(clicked()), this, SLOT(findOCSPPri()));
    connect( mOCSPSignerCertFindBtn, SIGNAL(clicked()), this, SLOT(findOCSPCert()));

    connect( mUseREGCheck, SIGNAL(clicked()), this, SLOT(checkREGUse()));
    connect( mUseCMPCheck, SIGNAL(clicked()), this, SLOT(checkCMPUse()));
    connect( mCMPRootCACertBtn, SIGNAL(clicked()), this, SLOT(findCMPRootCACert()));
    connect( mCMPCACertBtn, SIGNAL(clicked()), this, SLOT(findCMPCACert()));
    connect( mUseTSPCheck, SIGNAL(clicked()), this, SLOT(checkTSPUse()));

    connect( mTSPSrvCertFindBtn, SIGNAL(clicked()), this, SLOT(findTSPSrvCert()));

    connect( mUseSCEPCheck, SIGNAL(clicked()), this, SLOT(checkSCEPUse()));
    connect( mSCEPMutualAuthCheck, SIGNAL(clicked()), this, SLOT(checkSCEPMutualAuth()));
    connect( mSCEPPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(findSCEPPriKey()));
    connect( mSCEPCertFindBtn, SIGNAL(clicked()), this, SLOT(findSCEPCert()));

    mKMIPPasswdText->setEchoMode(QLineEdit::Password);

    QIntValidator *intVal = new QIntValidator( 0, 99 );
    mSlotIndexText->setValidator( intVal );

    initFontFamily();
    initialize();
#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    mgr->setServerStatus( mServerStatusCheck->checkState() == Qt::Checked );


    if( manApplet->isLicense() )
    {
        mgr->setSaveRemoteInfo( mSaveRemoteInfoCheck->checkState() == Qt::Checked );

        mgr->setUseLogTab( mUseLogTabCheck->checkState() == Qt::Checked );
        manApplet->mainWindow()->useLog( mUseLogTabCheck->checkState() == Qt::Checked );

        mgr->setLDAPHost( mLDAPHostText->text() );
        mgr->setLDAPPort( mLDAPPortText->text().toInt() );
        mgr->setBaseDN( mBaseDNText->text() );

        mgr->setDefaultECCParam( mDefaultECCParamCombo->currentText() );

        mgr->setPKCS11Use( mP11Group->isChecked() );
        mgr->setSlotIndex( mSlotIndexText->text().toInt() );
        mgr->setPKCS11LibraryPath( mLibraryP11PathText->text() );
    }

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        bool enabled = mCheckLatestVersionCheck->checkState() == Qt::Checked;
        AutoUpdateService::instance()->setAutoUpdateEnabled(enabled);
    }
#endif

    mgr->setListCount( mListCountCombo->currentText().toInt() );
    mgr->setDefaultHash( mDefaultHashCombo->currentText() );
    mgr->setHexAreaWidth( mHexAreaWidthCombo->currentText().toInt());

    mgr->setShowPriInfo( mShowPriKeyInfoCheck->isChecked() );
    mgr->setPKCS11Pin( mPINText->text() );

    bool language_changed = false;

    if( mLangCombo->currentIndex() != I18NHelper::getInstance()->preferredLanguage() )
    {
        language_changed = true;
        I18NHelper::getInstance()->setPreferredLanguage(mLangCombo->currentIndex());
    }

    if( language_changed && manApplet->yesOrNoBox(tr("You have changed language. Restart to apply it?"), this, true))
        manApplet->restartApp();

    if( manApplet->isPRO() )
    {
        mgr->setKMIPUse( mUseKMIPCheck->checkState() == Qt::Checked );
        mgr->setKMIPHost( mKMIPHostText->text() );
        mgr->setKMIPPort( mKMIPPortText->text() );
        mgr->setKMIPCACertPath( mKMIPCACertPathText->text() );
        mgr->setKMIPCertPath( mKMIPCertPathText->text() );
        mgr->setKMIPPrivateKeyPath( mKMIPPrivateKeyPathText->text() );
        mgr->setKMIPUserName( mKMIPUserNameText->text() );
        mgr->setKMIPPasswd( mKMIPPasswdText->text() );

        mgr->setOCSPUse( mUseOCSPCheck->checkState() == Qt::Checked );
        mgr->setOCSPURI( mOCSPURIText->text() );
        mgr->setOCSPSrvCertPath( mOCSPSrvCertPathText->text() );
        mgr->setOCSPAttachSign( mOCSPAttachSignCheck->checkState() == Qt::Checked );
        mgr->setOCSPSignerPriPath( mOCSPSignerPriPathText->text() );
        mgr->setOCSPSignerCertPath( mOCSPSignerCertPathText->text() );

        mgr->setREGUse( mUseREGCheck->checkState() == Qt::Checked );
        mgr->setREGURI( mREGURIText->text() );
        mgr->setREGAdminName( mREGAdminNameText->text() );
        mgr->setREGPassword( mREGPasswordText->text() );

        mgr->setCMPUse( mUseCMPCheck->checkState() == Qt::Checked );
        mgr->setCMPURI( mCMPURIText->text() );
        mgr->setCMPRootCACertPath( mCMPRootCACertPathText->text() );
        mgr->setCMPCACertPath( mCMPCACertPathText->text() );

        mgr->setTSPUse( mUseTSPCheck->checkState() == Qt::Checked );
        mgr->setTSPURI( mTSPURIText->text() );
        mgr->setTSPSrvCertPath( mTSPSrvCertPathText->text() );

        mgr->setSCEPUse( mUseSCEPCheck->checkState() == Qt::Checked );
        mgr->setSCEPURI( mSCEPURIText->text() );
        mgr->setSCEPMutualAuth( mSCEPMutualAuthCheck->checkState() == Qt::Checked );
        mgr->setSCEPPriKeyPath( mSCEPPriKeyPathText->text() );
        mgr->setSCEPCertPath( mSCEPCertPathText->text() );
    }

    mgr->setFontFamily( mFontFamilyCombo->currentText() );
}

void SettingsDlg::checkKMIPUse()
{
    bool bVal = mUseKMIPCheck->isChecked();

    mKMIPGroup->setEnabled( bVal );
}

void SettingsDlg::findCACert()
{
    QString strPath = mKMIPCACertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mKMIPCACertPathText->setText( fileName );
}

void SettingsDlg::findCert()
{
    QString strPath = mKMIPCertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mKMIPCertPathText->setText( fileName );
}

void SettingsDlg::findPrivateKey()
{
    QString strPath = mKMIPPrivateKeyPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() < 1 ) return;

    mKMIPPrivateKeyPathText->setText( fileName );
}

void SettingsDlg::findP11Path()
{
    QString strPath = mLibraryP11PathText->text();

#ifdef Q_OS_MAC
    if( strPath.length() < 1 ) strPath = "/usr/local/lib";
#else
    if( strPath.length() < 1 ) strPath = manApplet->curPath();
#endif

    QString fileName = findFile( this, JS_FILE_TYPE_DLL, strPath );
    if( fileName.length() < 1 ) return;

    mLibraryP11PathText->setText( fileName );
}

void SettingsDlg::checkOCSPUse()
{
    bool bVal = mUseOCSPCheck->isChecked();

    mOCSPGroup->setEnabled( bVal );
}

void SettingsDlg::checkOCSPAttachSign()
{
    bool bVal = mOCSPAttachSignCheck->isChecked();

    mOCSPSignerPriPathText->setEnabled(bVal);
    mOCSPSignerPriFindBtn->setEnabled(bVal);
    mOCSPSignerCertPathText->setEnabled(bVal);
    mOCSPSignerCertFindBtn->setEnabled(bVal);
}

void SettingsDlg::findOCSPSrvCert()
{
    QString strPath = mOCSPSrvCertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mOCSPSrvCertPathText->setText( fileName );
}

void SettingsDlg::findOCSPPri()
{
    QString strPath = mOCSPSignerPriPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() < 1 ) return;

    mOCSPSignerPriPathText->setText( fileName );
}

void SettingsDlg::findOCSPCert()
{
    QString strPath = mOCSPSignerCertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mOCSPSignerCertPathText->setText( fileName );
}

void SettingsDlg::checkREGUse()
{
    bool bVal = mUseREGCheck->isChecked();

    mREGGroup->setEnabled( bVal );
}

void SettingsDlg::checkCMPUse()
{
    bool bVal = mUseCMPCheck->isChecked();
    mCMPGroup->setEnabled( bVal );
}

void SettingsDlg::findCMPRootCACert()
{
    QString strPath = mCMPRootCACertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mCMPRootCACertPathText->setText( fileName );
}

void SettingsDlg::findCMPCACert()
{
    QString strPath = mCMPCACertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mCMPCACertPathText->setText( fileName );
}

void SettingsDlg::checkTSPUse()
{
    bool bVal = mUseTSPCheck->isChecked();
    mTSPGroup->setEnabled( bVal );
}

void SettingsDlg::findTSPSrvCert()
{
    QString strPath = mTSPSrvCertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mTSPSrvCertPathText->setText( fileName );
}

void SettingsDlg::checkSCEPUse()
{
    bool bVal = mUseSCEPCheck->isChecked();
    mSCEPGroup->setEnabled( bVal );

    checkSCEPMutualAuth();
}

void SettingsDlg::checkSCEPMutualAuth()
{
    bool bVal = mSCEPMutualAuthCheck->isChecked();

    mSCEPPriKeyPathText->setEnabled( bVal );
    mSCEPPriKeyFindBtn->setEnabled( bVal );
    mSCEPCertPathText->setEnabled( bVal );
    mSCEPCertFindBtn->setEnabled( bVal );
}

void SettingsDlg::findSCEPPriKey()
{
    QString strPath = mSCEPPriKeyPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() < 1 ) return;

    mSCEPPriKeyPathText->setText( fileName );
}

void SettingsDlg::findSCEPCert()
{
    QString strPath = mSCEPCertPathText->text();
    strPath = manApplet->curFilePath( strPath );

    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mSCEPCertPathText->setText( fileName );
}

void SettingsDlg::clickOK()
{
    updateSettings();
    QDialog::accept();
}

void SettingsDlg::clickCancel()
{
    reject();
}

void SettingsDlg::clickRestoreDefaults()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    QString strMsg = tr( "Are you sure you want to clear all the saved settings?" );

    bool bVal = manApplet->yesOrNoBox( strMsg, this, false );
    if( bVal == false ) return;

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        AutoUpdateService::instance()->setAutoUpdateEnabled(true);
    }
#endif

    mgr->removeSet( "Language", "current" );
    mgr->removeSet( kBehaviorGroup, kServerStatus );
    mgr->removeSet( kBehaviorGroup, kSaveRemoteInfo );
    mgr->removeSet( kBehaviorGroup, kUseLogTab );
    mgr->removeSet( kBehaviorGroup, kDefaultHash );
    mgr->removeSet( kBehaviorGroup, kDefaultECCParam );
    mgr->removeSet( kBehaviorGroup, kPKCS11Use );
    mgr->removeSet( kBehaviorGroup, kSlotIndex );
    mgr->removeSet( kBehaviorGroup, kP11LibPath );
    mgr->removeSet( kBehaviorGroup, kP11Pin );
    mgr->removeSet( kBehaviorGroup, kLDAPHost );
    mgr->removeSet( kBehaviorGroup, kLDAPPort );
    mgr->removeSet( kBehaviorGroup, kBaseDN );
    mgr->removeSet( kBehaviorGroup, kFontFamily );
    mgr->removeSet( kBehaviorGroup, kHexAreaWidth );
    mgr->removeSet( kBehaviorGroup, kSetListCount );
    mgr->removeSet( kBehaviorGroup, kShowPriInfo );

    if( manApplet->isPRO() == true )
    {
        mgr->removeSet( kBehaviorGroup, kKMIPUse );
        mgr->removeSet( kBehaviorGroup, kKMIPHost );
        mgr->removeSet( kBehaviorGroup, kKMIPPort );
        mgr->removeSet( kBehaviorGroup, kKMIPCACertPath );
        mgr->removeSet( kBehaviorGroup, kKMIPCertPath );
        mgr->removeSet( kBehaviorGroup, kKMIPPrivateKeyPath );
        mgr->removeSet( kBehaviorGroup, kKMIPUserName );
        mgr->removeSet( kBehaviorGroup, kKMIPPasswd );
        mgr->removeSet( kBehaviorGroup, kOCSPUse );
        mgr->removeSet( kBehaviorGroup, kOCSPURI );
        mgr->removeSet( kBehaviorGroup, kOCSPSrvCertPath );
        mgr->removeSet( kBehaviorGroup, kOCSPAttachSign );
        mgr->removeSet( kBehaviorGroup, kOCSPSignerPriPath );
        mgr->removeSet( kBehaviorGroup, kOCSPSignerCertPath );
        mgr->removeSet( kBehaviorGroup, kREGUse );
        mgr->removeSet( kBehaviorGroup, kREGURI );
        mgr->removeSet( kBehaviorGroup, kREGAdminName );
        mgr->removeSet( kBehaviorGroup, kREGPassword );
        mgr->removeSet( kBehaviorGroup, kCMPUse );
        mgr->removeSet( kBehaviorGroup, kCMPURI );
        mgr->removeSet( kBehaviorGroup, kCMPRootCACertPath );
        mgr->removeSet( kBehaviorGroup, kCMPCACertPath );
        mgr->removeSet( kBehaviorGroup, kTSPUse );
        mgr->removeSet( kBehaviorGroup, kTSPURI );
        mgr->removeSet( kBehaviorGroup, kTSPSrvCertPath );
        mgr->removeSet( kBehaviorGroup, kSCEPUse );
        mgr->removeSet( kBehaviorGroup, kSCEPURI );
        mgr->removeSet( kBehaviorGroup, kSCEPMutualAuth );
        mgr->removeSet( kBehaviorGroup, kSCEPPriPath );
        mgr->removeSet( kBehaviorGroup, kSCEPCertPath );
    }

    if( manApplet->yesOrNoBox(tr("Restored to default settings. Restart to apply it?"), this, true))
        manApplet->restartApp();

    close();
}

void SettingsDlg::initialize()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    Qt::CheckState state;
    const QStringList sHexWidthList = { "", "8", "16", "32", "64", "80" };

    mHexAreaWidthCombo->addItems(sHexWidthList);
    mHexAreaWidthCombo->setCurrentText( QString("%1").arg( mgr->getHexAreaWidth() ));

    state = mgr->serverStatus() ? Qt::Checked : Qt::Unchecked;
    mServerStatusCheck->setCheckState( state );

    if( manApplet->isLicense() )
    {
        state = mgr->saveRemoteInfo() ? Qt::Checked : Qt::Unchecked;
        mSaveRemoteInfoCheck->setCheckState( state );

        state = mgr->getUseLogTab() ? Qt::Checked : Qt::Unchecked;
        mUseLogTabCheck->setCheckState(state);

        mLDAPHostText->setText( mgr->LDAPHost() );
        mLDAPPortText->setText( QString("%1").arg( mgr->LDAPPort() ));
        mBaseDNText->setText( mgr->baseDN() );

        mDefaultECCParamCombo->addItems( kECCOptionList );
        mDefaultECCParamCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );

        mP11Group->setChecked( mgr->PKCS11Use() );
    }
    else
    {
        mSaveRemoteInfoCheck->setEnabled(false);
        mUseLogTabCheck->setEnabled(false);

        mDefaultECCParamLabel->setEnabled(false);
        mDefaultECCParamCombo->setEnabled(false);
        mLDAPGroup->setEnabled(false);
        mP11Group->setChecked( false );
        mP11Group->setDisabled( true );
    }

    mShowPriKeyInfoCheck->setChecked( mgr->getShowPriInfo() );


    mListCountCombo->addItems( kListCountList );


    QString strSlotIndex = QString( "%1" ).arg( mgr->slotIndex() );
    mSlotIndexText->setText( strSlotIndex );
    mLibraryP11PathText->setText( mgr->PKCS11LibraryPath() );
    mPINText->setText( mgr->PKCS11Pin() );
    mListCountCombo->setCurrentText( QString("%1").arg( mgr->listCount()));

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckLatestVersionCheck->setCheckState(state);
    }
#else
    mCheckLatestVersionCheck->hide();
#endif

    mDefaultHashCombo->addItems( kHashList );
    mDefaultHashCombo->setCurrentText( manApplet->settingsMgr()->defaultHash() );

    mFontFamilyCombo->setCurrentText( manApplet->settingsMgr()->getFontFamily() );

    mLangCombo->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());

    if( manApplet->isPRO() )
    {
        state = mgr->KMIPUse() ? Qt::Checked : Qt::Unchecked;
        mUseKMIPCheck->setCheckState( state );

        mKMIPHostText->setText( mgr->KMIPHost() );
        mKMIPPortText->setText( mgr->KMIPPort() );
        mKMIPCACertPathText->setText( mgr->KMIPCACertPath() );
        mKMIPCertPathText->setText( mgr->KMIPCertPath() );
        mKMIPPrivateKeyPathText->setText( mgr->KMIPPrivateKeyPath() );
        mKMIPUserNameText->setText( mgr->KMIPUserName() );
        mKMIPPasswdText->setText( mgr->KMIPPasswd() );

        checkKMIPUse();

        state = mgr->OCSPUse() ? Qt::Checked : Qt::Unchecked;

        mUseOCSPCheck->setCheckState(state);

        mOCSPURIText->setText( mgr->OCSPURI() );
        mOCSPSrvCertPathText->setText( mgr->OCSPSrvCertPath() );

        state = mgr->OCSPAttachSign() ? Qt::Checked : Qt::Unchecked;
        mOCSPAttachSignCheck->setCheckState(state);

        mOCSPSignerPriPathText->setText( mgr->OCSPSignerPriPath() );
        mOCSPSignerCertPathText->setText( mgr->OCSPSignerCertPath() );

        checkOCSPUse();
        checkOCSPAttachSign();

        state = mgr->REGUse() ? Qt::Checked : Qt::Unchecked;
        mUseREGCheck->setCheckState( state );

        mREGURIText->setText( mgr->REGURI() );
        mREGAdminNameText->setText( mgr->REGAdminName() );
        mREGPasswordText->setText( mgr->REGPassword() );

        checkREGUse();

        state = mgr->CMPUse() ? Qt::Checked : Qt::Unchecked;
        mUseCMPCheck->setCheckState( state );
        mCMPURIText->setText( mgr->CMPURI() );
        mCMPRootCACertPathText->setText( mgr->CMPRootCACertPath() );
        mCMPCACertPathText->setText( mgr->CMPCACertPath() );

        checkCMPUse();

        state = mgr->TSPUse() ? Qt::Checked : Qt::Unchecked;
        mUseTSPCheck->setCheckState( state );
        mTSPURIText->setText( mgr->TSPURI() );
        mTSPSrvCertPathText->setText( mgr->TSPSrvCertPath() );

        checkTSPUse();

        state = mgr->SCEPUse() ? Qt::Checked : Qt::Unchecked;
        mUseSCEPCheck->setCheckState( state );
        mSCEPURIText->setText( mgr->SCEPURI() );
        state = mgr->SCEPMutualAuth() ? Qt::Checked : Qt::Unchecked;
        mSCEPMutualAuthCheck->setCheckState( state );
        mSCEPPriKeyPathText->setText( mgr->SCEPPriKeyPath() );
        mSCEPCertPathText->setText( mgr->SCEPCertPath() );

        checkSCEPUse();
    }
    else
    {
        mTabWidget->removeTab( 8 );
        mTabWidget->removeTab( 7 );
        mTabWidget->removeTab( 6 );
        mTabWidget->removeTab( 5 );
        mTabWidget->removeTab( 4 );
        mTabWidget->removeTab( 3 );
        mTabWidget->removeTab( 2 );

        mServerStatusCheck->hide();
    }

    mTabWidget->setCurrentIndex(0);
}

void SettingsDlg::initFontFamily()
{
    QFontDatabase fontDB;
    QStringList fontList = fontDB.families();
    mFontFamilyCombo->addItems( fontList );
}
