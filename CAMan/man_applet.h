#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;
class ManTrayIcon;
class SettingsMgr;
class SettingsDlg;

class AboutDlg;
class ExportDlg;
class GetLDAPDlg;
class ImportDlg;
class MakeCertDlg;
class MakeCertPolicyDlg;
class MakeCRLDlg;
class MakeCRLPolicyDlg;
class MakeReqDlg;
class NewKeyDlg;
class PubLDAPDlg;
class RevokeCertDlg;
class CertInfoDlg;
class CRLInfoDlg;

class ManApplet : public QObject
{
    Q_OBJECT
public:
    explicit ManApplet(QObject *parent = nullptr);
    void start();

    MainWindow* mainWindow() { return main_win_; };
    SettingsMgr* settingsMgr() { return settings_mgr_; };
    AboutDlg* aboutDlg() { return  about_dlg_; };
    ExportDlg* exportDlg() { return export_dlg_; };
    GetLDAPDlg* getLDAPDlg() { return get_ldap_dlg_; };
    ImportDlg* importDlg() { return import_dlg_; };
    MakeCertDlg* makeCertDlg() { return make_cert_dlg_; };
    MakeCertPolicyDlg *makeCertPolicyDlg() { return make_cert_policy_dlg_; };
    MakeCRLDlg* makeCRLDlg() { return make_crl_dlg_; };
    MakeCRLPolicyDlg* makeCRLPolicyDlg() { return make_crl_policy_dlg_; };
    MakeReqDlg* makeReqDlg() { return make_req_dlg_; };
    NewKeyDlg* newKeyDlg() { return new_key_dlg_; };
    PubLDAPDlg* pubLDAPDlg() { return pub_ldap_dlg_; };
    RevokeCertDlg* revokeCertDlg() { return revoke_cert_dlg_; };
    SettingsDlg* settingsDlg() { return settings_dlg_; };
    CertInfoDlg* certInfoDlg() { return cert_info_dlg_; };
    CRLInfoDlg* crlInfoDlg() { return crl_info_dlg_; };

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

signals:

public slots:

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    ManTrayIcon* tray_icon_;
    SettingsMgr* settings_mgr_;
    AboutDlg* about_dlg_;
    ExportDlg* export_dlg_;
    GetLDAPDlg* get_ldap_dlg_;
    ImportDlg* import_dlg_;
    MakeCertDlg* make_cert_dlg_;
    MakeCertPolicyDlg* make_cert_policy_dlg_;
    MakeCRLDlg* make_crl_dlg_;
    MakeCRLPolicyDlg* make_crl_policy_dlg_;
    MakeReqDlg* make_req_dlg_;
    NewKeyDlg* new_key_dlg_;
    PubLDAPDlg* pub_ldap_dlg_;
    RevokeCertDlg* revoke_cert_dlg_;
    SettingsDlg* settings_dlg_;
    CertInfoDlg* cert_info_dlg_;
    CRLInfoDlg* crl_info_dlg_;

    bool in_exit_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
