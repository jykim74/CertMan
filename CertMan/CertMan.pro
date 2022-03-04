#-------------------------------------------------
#
# Project created by QtCreator 2019-09-25T13:38:41
#
#-------------------------------------------------

QT       += core gui sql charts

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CertMan
TEMPLATE = app
PROJECT_VERSION = "0.9.3"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += CAMAN_VERSION=$$PROJECT_VERSION
DEFINES += JS_PRO

CONFIG += sdk_no_version_check

OPENSSL_NAME = "openssl3"
#OPENSSL_NAME = "cmpossl"

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
        crl_info_dlg.cpp \
        crl_profile_rec.cpp \
        crl_rec.cpp \
        db_mgr.cpp \
        export_dlg.cpp \
        get_ldap_dlg.cpp \
        i18n_helper.cpp \
        import_dlg.cpp \
        key_pair_rec.cpp \
        kms_attrib_rec.cpp \
        kms_rec.cpp \
        main.cpp \
        mainwindow.cpp \
        make_cert_dlg.cpp \
        make_cert_profile_dlg.cpp \
        make_crl_dlg.cpp \
        make_crl_profile_dlg.cpp \
        make_req_dlg.cpp \
        man_applet.cpp \
        man_tray_icon.cpp \
        man_tree_item.cpp \
        man_tree_model.cpp \
        man_tree_view.cpp \
        new_key_dlg.cpp \
        pin_dlg.cpp \
        profile_ext_rec.cpp \
        pub_ldap_dlg.cpp \
        req_rec.cpp \
        revoke_cert_dlg.cpp \
        revoke_rec.cpp \
        search_menu.cpp \
        server_status_dlg.cpp \
        server_status_service.cpp \
        settings_dlg.cpp \
        settings_mgr.cpp \
        signer_dlg.cpp \
        signer_rec.cpp \
        stat_form.cpp \
        tsp_dlg.cpp \
        tsp_rec.cpp \
        tst_info_dlg.cpp \
        user_dlg.cpp \
        user_rec.cpp

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
        crl_info_dlg.h \
        crl_profile_rec.h \
        crl_rec.h \
        db_mgr.h \
        export_dlg.h \
        get_ldap_dlg.h \
        i18n_helper.h \
        import_dlg.h \
        key_pair_rec.h \
        kms_attrib_rec.h \
        kms_rec.h \
        mainwindow.h \
        make_cert_dlg.h \
        make_cert_profile_dlg.h \
        make_crl_dlg.h \
        make_crl_profile_dlg.h \
        make_req_dlg.h \
        man_applet.h \
        man_tray_icon.h \
        man_tree_item.h \
        man_tree_model.h \
        man_tree_view.h \
        new_key_dlg.h \
        pin_dlg.h \
        profile_ext_rec.h \
        pub_ldap_dlg.h \
        req_rec.h \
        revoke_cert_dlg.h \
        revoke_rec.h \
        search_menu.h \
        server_status_dlg.h \
        server_status_service.h \
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
        user_rec.h

FORMS += \
        about_dlg.ui \
        admin_dlg.ui \
        cert_info_dlg.ui \
        crl_info_dlg.ui \
        export_dlg.ui \
        get_ldap_dlg.ui \
        import_dlg.ui \
        mainwindow.ui \
        make_cert_dlg.ui \
        make_cert_profile_dlg.ui \
        make_cert_profile_dlg.ui \
        make_crl_dlg.ui \
        make_crl_profile_dlg.ui \
        make_crl_profile_dlg.ui \
        make_req_dlg.ui \
        new_key_dlg.ui \
        pin_dlg.ui \
        pub_ldap_dlg.ui \
        revoke_cert_dlg.ui \
        server_status_dlg.ui \
        settings_dlg.ui \
        signer_dlg.ui \
        stat_form.ui \
        statistics_form.ui \
        tsp_dlg.ui \
        tst_info_dlg.ui \
        user_dlg.ui

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

    debug {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
        LIBS += -L"../../PKILib/lib/mac/debug/"$${OPENSSL_NAME}"/lib" -lcrypto
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Release" -lPKILib
        LIBS += -L"../../PKILib/lib/mac/"$${OPENSSL_NAME}"/lib" -lcrypto
    }

    LIBS += -L"/usr/local/lib" -lltdl

    LIBS += -lldap -llber
}

win32 {
    DEFINES += _AUTO_UPDATE
    RC_ICONS = certman.ico

    contains(QT_ARCH, i386) {
        message( "32bit" )
        INCLUDEPATH += "../../PKILib/lib/win32/winsparkle/include"
        INCLUDEPATH += "C:\msys64\mingw32\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib
            LIBS += -L"../../PKILib/lib/win32/debug/"$${OPENSSL_NAME}"/lib" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib
            LIBS += -L"../../PKILib/lib/win32/"$${OPENSSL_NAME}"/lib" -lcrypto -lssl
        }

        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lldap -llber
        LIBS += -L"../../PKILib/lib/win32/winsparkle/Release" -lWinSparkle -lws2_32
    } else {
        message( "64bit" );
        INCLUDEPATH += "../../PKILib/lib/win64/winsparkle/include"
        INCLUDEPATH += "C:\msys64\mingw64\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug/debug" -lPKILib
            LIBS += -L"../../PKILib/lib/win64/debug/"$${OPENSSL_NAME}"/lib64" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release/release" -lPKILib
            LIBS += -L"../../PKILib/lib/win64/"$${OPENSSL_NAME}"/lib64" -lcrypto -lssl
        }

        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lldap -llber
        LIBS += -L"../../PKILib/lib/win64/winsparkle/x64/Release" -lWinSparkle -lws2_32
    }
}

linux {
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/linux/debug/"$${OPENSSL_NAME}"/lib" -lcrypto
    LIBS += -lltdl -lldap -llber
}

DISTFILES +=
