#-------------------------------------------------
#
# Project created by QtCreator 2019-09-25T13:38:41
#
#-------------------------------------------------

QT       += core gui sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CAMan
TEMPLATE = app
PROJECT_VERSION = "0.9.1"

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += CAMAN_VERSION=$$PROJECT_VERSION
CONFIG += sdk_no_version_check

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        about_dlg.cpp \
        auto_update_service.cpp \
        cert_info_dlg.cpp \
        cert_policy_rec.cpp \
        cert_rec.cpp \
        crl_info_dlg.cpp \
        crl_policy_rec.cpp \
        crl_rec.cpp \
        db_mgr.cpp \
        export_dlg.cpp \
        get_ldap_dlg.cpp \
        i18n_helper.cpp \
        import_dlg.cpp \
        key_pair_rec.cpp \
        main.cpp \
        mainwindow.cpp \
        make_cert_dlg.cpp \
        make_cert_policy_dlg.cpp \
        make_crl_dlg.cpp \
        make_crl_policy_dlg.cpp \
        make_req_dlg.cpp \
        man_applet.cpp \
        man_tray_icon.cpp \
        man_tree_item.cpp \
        man_tree_model.cpp \
        man_tree_view.cpp \
        new_key_dlg.cpp \
        policy_ext_rec.cpp \
        pub_ldap_dlg.cpp \
        req_rec.cpp \
        revoke_cert_dlg.cpp \
        revoke_rec.cpp \
        settings_dlg.cpp \
        settings_mgr.cpp

HEADERS += \
        about_dlg.h \
        auto_update_service.h \
        cert_info_dlg.h \
        cert_policy_rec.h \
        cert_rec.h \
        crl_info_dlg.h \
        crl_policy_rec.h \
        crl_rec.h \
        db_mgr.h \
        export_dlg.h \
        get_ldap_dlg.h \
        i18n_helper.h \
        import_dlg.h \
        key_pair_rec.h \
        mainwindow.h \
        make_cert_dlg.h \
        make_cert_policy_dlg.h \
        make_crl_dlg.h \
        make_crl_policy_dlg.h \
        make_req_dlg.h \
        man_applet.h \
        man_tray_icon.h \
        man_tree_item.h \
        man_tree_model.h \
        man_tree_view.h \
        new_key_dlg.h \
        policy_ext_rec.h \
        pub_ldap_dlg.h \
        req_rec.h \
        revoke_cert_dlg.h \
        revoke_rec.h \
        settings_dlg.h \
        settings_mgr.h \
        singleton.h

FORMS += \
        about_dlg.ui \
        cert_info_dlg.ui \
        crl_info_dlg.ui \
        export_dlg.ui \
        get_ldap_dlg.ui \
        import_dlg.ui \
        mainwindow.ui \
        make_cert_dlg.ui \
        make_cert_policy_dlg.ui \
        make_crl_dlg.ui \
        make_crl_policy_dlg.ui \
        make_req_dlg.ui \
        new_key_dlg.ui \
        pub_ldap_dlg.ui \
        revoke_cert_dlg.ui \
        settings_dlg.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    caman.qrc

TRANSLATIONS += i18n/caman_ko_KR.ts

DEFINES += _AUTO_UPDATE

INCLUDEPATH += "../../PKILib"

mac {
    ICON = images/caman.icns

    QMAKE_LFLAGS += -Wl,-rpath,@loader_path/../Frameworks
    HEADERS += mac_sparkle_support.h
    OBJECTIVE_SOURCES += mac_sparkle_support.mm
    LIBS += -framework AppKit
    LIBS += -framework Carbon
    LIBS += -framework Foundation
    LIBS += -framework ApplicationServices
    LIBS += -framework Sparkle
    INCLUDEPATH += "/usr/local/Sparkle.framework/Headers"

    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/openssl/lib" -lcrypto
    LIBS += -lldap -llber
}

win32 {
    INCLUDEPATH += "../../PKILib/lib/win32/winsparkle/include"
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_12_2_MinGW_32_bit-Debug/debug" -lPKILib
    LIBS += -L"../../PKILib/lib/win32/cmpossl-mingw32/lib" -lcrypto
    LIBS += -L"../../PKILib/lib/win32/winsparkle/Release" -lWinSparkle
}
