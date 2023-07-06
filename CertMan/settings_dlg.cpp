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

    connect( mUseP11Check, SIGNAL(clicked()), this, SLOT(checkP11Use()));
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
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    mgr->setSaveDBPath( mSaveDBPathCheck->checkState() == Qt::Checked );
    mgr->setServerStatus( mServerStatusCheck->checkState() == Qt::Checked );

    if( manApplet->isLicense() )
    {
        mgr->setShowLogTab( mShowLogTabCheck->checkState() == Qt::Checked );
        manApplet->mainWindow()->logView( mShowLogTabCheck->checkState() == Qt::Checked );
    }

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        bool enabled = mCheckLatestVersionCheck->checkState() == Qt::Checked;
        AutoUpdateService::instance()->setAutoUpdateEnabled(enabled);
    }
#endif

    mgr->setPKCS11Use( mUseP11Check->checkState() == Qt::Checked );
    mgr->setSlotIndex( mSlotIndexText->text().toInt() );
    mgr->setPKCS11LibraryPath( mLibraryP11PathText->text() );
    mgr->setLDAPHost( mLDAPHostText->text() );
    mgr->setLDAPPort( mLDAPPortText->text().toInt() );
    mgr->setBaseDN( mBaseDNText->text() );
    mgr->setListCount( mListCountCombo->currentText().toInt() );

    mgr->setDefaultHash( mDefaultHashCombo->currentText() );
    mgr->setDefaultECCParam( mDefaultECCParamCombo->currentText() );
    mgr->setPKCS11Pin( mPINText->text() );

    bool language_changed = false;

    if( mLangCombo->currentIndex() != I18NHelper::getInstance()->preferredLanguage() )
    {
        language_changed = true;
        I18NHelper::getInstance()->setPreferredLanguage(mLangCombo->currentIndex());
    }

    if( language_changed && manApplet->yesOrNoBox(tr("You have changed language. Restart to apply it?"), this, true))
        manApplet->restartApp();

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
    mgr->setFontFamily( mFontFamilyCombo->currentText() );
}

void SettingsDlg::checkP11Use()
{
    bool val = mUseP11Check->isChecked();
    mSlotIndexText->setEnabled(val);
    mLibraryP11PathText->setEnabled(val);
    mP11FindBtn->setEnabled(val);
    mPINText->setEnabled(val);
}

void SettingsDlg::checkKMIPUse()
{
    bool bVal = mUseKMIPCheck->isChecked();

    mKMIPGroup->setEnabled( bVal );
}

void SettingsDlg::findCACert()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mKMIPCACertPathText->setText( fileName );
}

void SettingsDlg::findCert()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mKMIPCertPathText->setText( fileName );
}

void SettingsDlg::findPrivateKey()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() < 1 ) return;

    mKMIPPrivateKeyPathText->setText( fileName );
}

void SettingsDlg::findP11Path()
{
#ifdef Q_OS_MAC
    QString strPath = "/usr/local/lib";
#else
    QString strPath = manApplet->getSetPath();
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
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mOCSPSrvCertPathText->setText( fileName );
}

void SettingsDlg::findOCSPPri()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() < 1 ) return;

    mOCSPSignerPriPathText->setText( fileName );
}

void SettingsDlg::findOCSPCert()
{
    QString strPath = manApplet->getSetPath();
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
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mCMPRootCACertPathText->setText( fileName );
}

void SettingsDlg::findCMPCACert()
{
    QString strPath = manApplet->getSetPath();
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
    QString strPath = manApplet->getSetPath();
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
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_PRIKEY, strPath );
    if( fileName.length() < 1 ) return;

    mSCEPPriKeyPathText->setText( fileName );
}

void SettingsDlg::findSCEPCert()
{
    QString strPath = manApplet->getSetPath();
    QString fileName = findFile( this, JS_FILE_TYPE_CERT, strPath );
    if( fileName.length() < 1 ) return;

    mSCEPCertPathText->setText( fileName );
}

void SettingsDlg::accept()
{
    updateSettings();
    QDialog::accept();
}

void SettingsDlg::initialize()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    Qt::CheckState state;

    state = mgr->saveDBPath() ? Qt::Checked : Qt::Unchecked;
    mSaveDBPathCheck->setCheckState(state);

    state = mgr->serverStatus() ? Qt::Checked : Qt::Unchecked;
    mServerStatusCheck->setCheckState( state );

    if( manApplet->isLicense() )
    {
        state = mgr->showLogTab() ? Qt::Checked : Qt::Unchecked;
        mShowLogTabCheck->setCheckState(state);
    }
    else
        mShowLogTabCheck->hide();

    state = mgr->PKCS11Use() ? Qt::Checked : Qt::Unchecked;
    mUseP11Check->setCheckState( state );

    checkP11Use();

    mListCountCombo->addItems( kListCountList );


    QString strSlotIndex = QString( "%1" ).arg( mgr->slotIndex() );
    mSlotIndexText->setText( strSlotIndex );
    mLibraryP11PathText->setText( mgr->PKCS11LibraryPath() );
    mPINText->setText( mgr->PKCS11Pin() );
    mListCountCombo->setCurrentText( QString("%1").arg( mgr->listCount()));
    mLDAPHostText->setText( mgr->LDAPHost() );
    mLDAPPortText->setText( QString("%1").arg( mgr->LDAPPort() ));
    mBaseDNText->setText( mgr->baseDN() );

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

    mDefaultECCParamCombo->addItems( kECCOptionList );
    mDefaultECCParamCombo->setCurrentText( manApplet->settingsMgr()->defaultECCParam() );

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
    }

    mTabWidget->setCurrentIndex(0);
}

void SettingsDlg::initFontFamily()
{
    QFontDatabase fontDB;
    QStringList fontList = fontDB.families();
    mFontFamilyCombo->addItems( fontList );
}
