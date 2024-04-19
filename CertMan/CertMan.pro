#-------------------------------------------------
#
# Project created by QtCreator 2019-09-25T13:38:41
#
#-------------------------------------------------

QT       += core gui sql network
# QT += charts

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CertMan
TEMPLATE = app
PROJECT_VERSION = "1.8.0"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += CERTMAN_VERSION=$$PROJECT_VERSION

# DEFINES += _USE_RC_LCN
# DEFINES += JS_PRO
# DEFINES += USE_SCEP
# DEFINES += USE_CMP
# DEFINES += USE_OCSP

CONFIG += sdk_no_version_check

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        about_dlg.cpp \
        admin_dlg.cpp \
        admin_rec.cpp \
        audit_rec.cpp \
        auto_update_service.cpp \
        cert_info_dlg.cpp \
        cert_profile_rec.cpp \
        cert_rec.cpp \
        commons.cpp \
        config_dlg.cpp \
        config_rec.cpp \
        crl_info_dlg.cpp \
        crl_profile_rec.cpp \
        crl_rec.cpp \
        csr_info_dlg.cpp \
        db_mgr.cpp \
        export_dlg.cpp \
        get_uri_dlg.cpp \
        i18n_helper.cpp \
        import_dlg.cpp \
        key_pair_rec.cpp \
        kms_attrib_rec.cpp \
        kms_rec.cpp \
        lcn_info_dlg.cpp \
        login_dlg.cpp \
        main.cpp \
        mainwindow.cpp \
        make_cert_dlg.cpp \
        make_cert_profile_dlg.cpp \
        make_crl_dlg.cpp \
        make_crl_profile_dlg.cpp \
        make_dn_dlg.cpp \
        make_req_dlg.cpp \
        man_applet.cpp \
        man_tray_icon.cpp \
        man_tree_item.cpp \
        man_tree_model.cpp \
        man_tree_view.cpp \
        new_key_dlg.cpp \
        pin_dlg.cpp \
        pri_key_info_dlg.cpp \
        profile_ext_rec.cpp \
        pub_ldap_dlg.cpp \
        remote_db_dlg.cpp \
        renew_cert_dlg.cpp \
        req_rec.cpp \
        revoke_cert_dlg.cpp \
        revoke_rec.cpp \
        search_form.cpp \
        server_status_dlg.cpp \
        server_status_service.cpp \
        set_pass_dlg.cpp \
        settings_dlg.cpp \
        settings_mgr.cpp \
        signer_dlg.cpp \
        signer_rec.cpp \
        stat_form.cpp \
        tsp_dlg.cpp \
        tsp_rec.cpp \
        tst_info_dlg.cpp \
        user_dlg.cpp \
        user_rec.cpp \
        pki_srv_dlg.cpp \
        copy_right_dlg.cpp

HEADERS += \
        about_dlg.h \
        admin_dlg.h \
        admin_rec.h \
        audit_rec.h \
        auto_update_service.h \
        cert_info_dlg.h \
        cert_profile_rec.h \
        cert_rec.h \
        commons.h \
        config_dlg.h \
        config_rec.h \
        crl_info_dlg.h \
        crl_profile_rec.h \
        crl_rec.h \
        csr_info_dlg.h \
        db_mgr.h \
        export_dlg.h \
        get_uri_dlg.h \
        i18n_helper.h \
        import_dlg.h \
        key_pair_rec.h \
        kms_attrib_rec.h \
        kms_rec.h \
        lcn_info_dlg.h \
        login_dlg.h \
        mainwindow.h \
        make_cert_dlg.h \
        make_cert_profile_dlg.h \
        make_crl_dlg.h \
        make_crl_profile_dlg.h \
        make_dn_dlg.h \
        make_req_dlg.h \
        man_applet.h \
        man_tray_icon.h \
        man_tree_item.h \
        man_tree_model.h \
        man_tree_view.h \
        new_key_dlg.h \
        pin_dlg.h \
        pri_key_info_dlg.h \
        profile_ext_rec.h \
        pub_ldap_dlg.h \
        remote_db_dlg.h \
        renew_cert_dlg.h \
        req_rec.h \
        revoke_cert_dlg.h \
        revoke_rec.h \
        search_form.h \
        server_status_dlg.h \
        server_status_service.h \
        set_pass_dlg.h \
        settings_dlg.h \
        settings_mgr.h \
        signer_dlg.h \
        signer_rec.h \
        singleton.h \
        stat_form.h \
        tsp_dlg.h \
        tsp_rec.h \
        tst_info_dlg.h \
        user_dlg.h \
        user_rec.h \
        pki_srv_dlg.h \
        copy_right_dlg.h

FORMS += \
        about_dlg.ui \
        admin_dlg.ui \
        cert_info_dlg.ui \
        config_dlg.ui \
        crl_info_dlg.ui \
        csr_info_dlg.ui \
        export_dlg.ui \
        get_uri_dlg.ui \
        import_dlg.ui \
        lcn_info_dlg.ui \
        login_dlg.ui \
        mainwindow.ui \
        make_cert_dlg.ui \
        make_cert_profile_dlg.ui \
        make_cert_profile_dlg.ui \
        make_crl_dlg.ui \
        make_crl_profile_dlg.ui \
        make_crl_profile_dlg.ui \
        make_dn_dlg.ui \
        make_req_dlg.ui \
        new_key_dlg.ui \
        pin_dlg.ui \
        pri_key_info_dlg.ui \
        pub_ldap_dlg.ui \
        remote_db_dlg.ui \
        renew_cert_dlg.ui \
        revoke_cert_dlg.ui \
        search_form.ui \
        server_status_dlg.ui \
        set_pass_dlg.ui \
        settings_dlg.ui \
        signer_dlg.ui \
        stat_form.ui \
        statistics_form.ui \
        tsp_dlg.ui \
        tst_info_dlg.ui \
        user_dlg.ui \
        pki_srv_dlg.ui \
        copy_right_dlg.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    certman.qrc

TRANSLATIONS += i18n/certman_ko_KR.ts

INCLUDEPATH += "../../PKILib"

mac {
    DEFINES += _AUTO_UPDATE
    QMAKE_INFO_PLIST = info.plist
    ICON = images/certman.icns

    QMAKE_LFLAGS += -Wl,-rpath,@loader_path/../Frameworks
    HEADERS += mac_sparkle_support.h
    OBJECTIVE_SOURCES += mac_sparkle_support.mm
    LIBS += -framework AppKit
    LIBS += -framework Carbon
    LIBS += -framework Foundation
    LIBS += -framework ApplicationServices
    LIBS += -framework Sparkle
    INCLUDEPATH += "/usr/local/Sparkle.framework/Headers"
    INCLUDEPATH += "/usr/local/include"

    CONFIG( debug, debug | release ) {
        message( "CertMan Debug" );
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug" -lPKILib
        LIBS += -L"../../lib/mac/debug/openssl3/lib" -lcrypto -lssl
        INCLUDEPATH += "../../lib/mac/debug/openssl3/include"
    } else {
        message( "CertMan Release" );
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release" -lPKILib
        LIBS += -L"../../lib/mac/openssl3/lib" -lcrypto -lssl
        INCLUDEPATH += "../../lib/mac/openssl3/include"
    }

    LIBS += -L"/usr/local/lib" -lltdl

    LIBS += -lldap -llber
}

win32 {
    DEFINES += _AUTO_UPDATE
    RC_ICONS = certman.ico

    contains(QT_ARCH, i386) {
        message( "32bit" )
        INCLUDEPATH += "../../lib/win32/winsparkle/include"
        INCLUDEPATH += "C:\msys64\mingw32\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug" -lPKILib
            LIBS += -L"../../lib/win32/debug/openssl3/lib" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release" -lPKILib
            LIBS += -L"../../lib/win32/openssl3/lib" -lcrypto -lssl
        }

        LIBS += -L"../../lib/win32" -lltdl -lldap -llber
        LIBS += -L"../../lib/win32/winsparkle/lib" -lWinSparkle -lws2_32
    } else {
        message( "64bit" );
        INCLUDEPATH += "../../lib/win64/winsparkle/include"
        INCLUDEPATH += "C:\msys64\mingw64\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug" -lPKILib
            LIBS += -L"../../lib/win64/debug/openssl3/lib64" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release" -lPKILib
            LIBS += -L"../../lib/win64/openssl3/lib64" -lcrypto -lssl
        }

        LIBS += -L"../../lib/win64" -lltdl -lldap -llber
        LIBS += -L"../../lib/win64/winsparkle/lib" -lWinSparkle -lws2_32
    }
}

linux {
    CONFIG( debug, debug | release ) {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug" -lPKILib
        LIBS += -L"../../lib/linux/debug/openssl3/lib64" -lcrypto -lssl
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Release" -lPKILib
        LIBS += -L"../../lib/linux/openssl3/lib64" -lcrypto -lssl
    }

    LIBS += -lltdl -lldap -llber
}

DISTFILES += \
    i18n/certman_ko_KR.qm
