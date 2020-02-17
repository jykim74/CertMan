#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;
class ManTrayIcon;
class SettingsMgr;

class AboutDlg;
class ImportDlg;

class MakeCRLDlg;
class MakeCRLPolicyDlg;

class RevokeCertDlg;
class CRLInfoDlg;
class CheckCertDlg;

class SignerDlg;

class ManApplet : public QObject
{
    Q_OBJECT
public:
    ManApplet(QObject *parent = nullptr);
    ~ManApplet();

    void start();

    MainWindow* mainWindow() { return main_win_; };
    ManTrayIcon* trayIcon() { return tray_icon_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };
    AboutDlg* aboutDlg() { return  about_dlg_; };
    ImportDlg* importDlg() { return import_dlg_; };

    MakeCRLDlg* makeCRLDlg() { return make_crl_dlg_; };
    MakeCRLPolicyDlg* makeCRLPolicyDlg() { return make_crl_policy_dlg_; };

    RevokeCertDlg* revokeCertDlg() { return revoke_cert_dlg_; };
    CRLInfoDlg* crlInfoDlg() { return crl_info_dlg_; };
    CheckCertDlg* checkCertDlg() { return check_cert_dlg_; };

    SignerDlg* signerDlg() { return signer_dlg_; };
    void* P11CTX() { return p11_ctx_; };

    void messageBox(const QString& msg, QWidget *parent=0);
    void warningBox(const QString& msg, QWidget *parent=0);
    bool yesOrNoBox(const QString& msg, QWidget *parent=0, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString getBrand();
    void restartApp();

private:
    int loadPKCS11();

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    ManTrayIcon* tray_icon_;
    SettingsMgr* settings_mgr_;
    AboutDlg* about_dlg_;
    ImportDlg* import_dlg_;

    MakeCRLDlg* make_crl_dlg_;
    MakeCRLPolicyDlg* make_crl_policy_dlg_;

    RevokeCertDlg* revoke_cert_dlg_;
    CRLInfoDlg* crl_info_dlg_;
    CheckCertDlg* check_cert_dlg_;

    SignerDlg* signer_dlg_;
    void*       p11_ctx_;

    bool in_exit_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
