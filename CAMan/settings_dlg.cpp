#include <QtGlobal>
#include <QtWidgets>

#include "i18n_helper.h"
#include "settings_dlg.h"
#include "ui_settings_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "settings_mgr.h"

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

    mKMIPPasswdText->setEchoMode(QLineEdit::Password);

    initialize();
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    mgr->setSaveDBPath( mSaveDBPathCheck->checkState() == Qt::Checked );

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        bool enabled = mCheckLatestVersionCheck->checkState() == Qt::Checked;
        AutoUpdateService::instance()->setAutoUpdateEnabled(enabled);
    }
#endif

    mgr->setPKCS11Use( mUseP11Check->checkState() == Qt::Checked );
    mgr->setSlotID( mSlotIDText->text().toInt() );
    mgr->setPKCS11LibraryPath( mLibraryP11PathText->text() );
    mgr->setBaseDN( mBaseDNText->text() );
    mgr->setListCount( mListCountText->text().toInt() );

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
}

void SettingsDlg::checkP11Use()
{
    bool val = mUseP11Check->isChecked();
    mSlotIDText->setEnabled(val);
    mLibraryP11PathText->setEnabled(val);
    mP11FindBtn->setEnabled(val);
}

void SettingsDlg::checkKMIPUse()
{
    bool bVal = mUseKMIPCheck->isChecked();

    mKMIPGroup->setEnabled( bVal );
}

void SettingsDlg::findCACert()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("CA Certificate File"),
                                                     QDir::currentPath(),
                                                     tr("Certificate Files (*.crt);;DER Files (*.der);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mKMIPCACertPathText->setText( fileName );
}

void SettingsDlg::findCert()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Certificate File"),
                                                     QDir::currentPath(),
                                                     tr("Certificate Files (*.crt);;DER Files (*.der);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mKMIPCertPathText->setText( fileName );
}

void SettingsDlg::findPrivateKey()
{
    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Private Key File"),
                                                     QDir::currentPath(),
                                                     tr("PrivateKey Files (*.key);;DER Files (*.der);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mKMIPPrivateKeyPathText->setText( fileName );
}

void SettingsDlg::findP11Path()
{
    QString strPath = "/usr/local/lib";

    QFileDialog::Options options;
    options |= QFileDialog::DontUseNativeDialog;

    QString selectedFilter;
    QString fileName = QFileDialog::getOpenFileName( this,
                                                     tr("Open cryptoki library file"),
                                                     strPath,
                                                     tr("DLL Files (*.dll);;SO Files (*.so);;All Files (*.*)"),
                                                     &selectedFilter,
                                                     options );

    mLibraryP11PathText->setText( fileName );
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

    state = mgr->PKCS11Use() ? Qt::Checked : Qt::Unchecked;
    mUseP11Check->setCheckState( state );

    checkP11Use();


    QString strSlotID = QString( "%1" ).arg( mgr->slotID() );
    mSlotIDText->setText( strSlotID );
    mLibraryP11PathText->setText( mgr->PKCS11LibraryPath() );
    mListCountText->setText( QString("%1").arg( mgr->listCount() ));
    mBaseDNText->setText( mgr->baseDN() );

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckLatestVersionCheck->setCheckState(state);
    }
#endif

    mLangCombo->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());

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
    mTabWidget->setCurrentIndex(0);
}
