cmake_minimum_required(VERSION 3.5)

project(CertMan
    VERSION 1.9.0
    DESCRIPTION "CertMan Application"
    LANGUAGES CXX )

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Set up AUTOMOC and some sensible defaults for runtime execution
# When using Qt 6.3, you can replace the code block below with
# qt_standard_project_setup()
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(QT NAMES Qt5 Qt6 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Gui)
find_package(Qt${QT_VERSION_MAJOR} OPTIONAL_COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Sql)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Network)

add_definitions( -D_USE_LCN_SRV )
# add_definitions( -DJS_PRO )

# Qt Charts 라이브러리는 GPL 라이센스라서 LGPL-3.0 라이센스로 사용하면 안됨
# find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Charts)
# find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core5Compat)

if(APPLE)
    SET(platform_specific_sources ${platform_specific_sources} mac_sparkle_support.mm)
    SET(platform_specific_headers ${platform_specific_headers} mac_sparkle_support.h)
    SET_SOURCE_FILES_PROPERTIES(mac_sparkle_support.mm PROPERTIES COMPILE_FLAGS -fobjc-arc)
    SET(SPARKLE_FRAMEWORK /usr/local/Sparkle.framework)
    INCLUDE_DIRECTORIES(${SPARKLE_FRAMEWORK}/Headers)
endif()

set(PROJECT_SRC
    about_dlg.cpp
    admin_dlg.cpp
    admin_rec.cpp
    audit_rec.cpp
    auto_update_service.cpp
    cert_info_dlg.cpp
    cert_profile_rec.cpp
    cert_rec.cpp
    commons.cpp
    config_dlg.cpp
    config_rec.cpp
    crl_info_dlg.cpp
    crl_profile_rec.cpp
    crl_rec.cpp
    csr_info_dlg.cpp
    db_mgr.cpp
    export_dlg.cpp
    get_uri_dlg.cpp
    i18n_helper.cpp
    import_dlg.cpp
    key_pair_rec.cpp
    kms_attrib_rec.cpp
    kms_rec.cpp
    lcn_info_dlg.cpp
    login_dlg.cpp
    main.cpp
    mainwindow.cpp
    make_cert_dlg.cpp
    make_cert_profile_dlg.cpp
    make_crl_dlg.cpp
    make_crl_profile_dlg.cpp
    make_req_dlg.cpp
    man_applet.cpp
    man_tray_icon.cpp
    man_tree_item.cpp
    man_tree_model.cpp
    man_tree_view.cpp
    new_key_dlg.cpp
    pin_dlg.cpp
    pri_key_info_dlg.cpp
    profile_ext_rec.cpp
    pub_ldap_dlg.cpp
    remote_db_dlg.cpp
    renew_cert_dlg.cpp
    req_rec.cpp
    revoke_cert_dlg.cpp
    revoke_rec.cpp
    search_form.cpp
    server_status_dlg.cpp
    server_status_service.cpp
    set_pass_dlg.cpp
    settings_dlg.cpp
    settings_mgr.cpp
    signer_dlg.cpp
    signer_rec.cpp
    stat_form.cpp
    tsp_dlg.cpp
    tsp_rec.cpp
    tst_info_dlg.cpp
    user_dlg.cpp
    user_rec.cpp
    make_dn_dlg.cpp
    ${platform_specific_sources}
)

set( PROJECT_HEADER
    about_dlg.h
    admin_dlg.h
    admin_rec.h
    audit_rec.h
    auto_update_service.h
    cert_info_dlg.h
    cert_profile_rec.h
    cert_rec.h
    commons.h
    config_dlg.h
    config_rec.h
    crl_info_dlg.h
    crl_profile_rec.h
    crl_rec.h
    csr_info_dlg.h
    db_mgr.h
    export_dlg.h
    get_uri_dlg.h
    i18n_helper.h
    import_dlg.h
    key_pair_rec.h
    kms_attrib_rec.h
    kms_rec.h
    lcn_info_dlg.h
    login_dlg.h
    mainwindow.h
    make_cert_dlg.h
    make_cert_profile_dlg.h
    make_crl_dlg.h
    make_crl_profile_dlg.h
    make_req_dlg.h
    man_applet.h
    man_tray_icon.h
    man_tree_item.h
    man_tree_model.h
    man_tree_view.h
    new_key_dlg.h
    pin_dlg.h
    pri_key_info_dlg.h
    profile_ext_rec.h
    pub_ldap_dlg.h
    remote_db_dlg.h
    renew_cert_dlg.h
    req_rec.h
    revoke_cert_dlg.h
    revoke_rec.h
    search_form.h
    server_status_dlg.h
    server_status_service.h
    set_pass_dlg.h
    settings_dlg.h
    settings_mgr.h
    signer_dlg.h
    signer_rec.h
    singleton.h
    stat_form.h
    tsp_dlg.h
    tsp_rec.h
    tst_info_dlg.h
    user_dlg.h
    user_rec.h
    make_dn_dlg.h
    ${platform_specific_headers}
)

set( PROJECT_FORM
    about_dlg.ui
    admin_dlg.ui
    cert_info_dlg.ui
    config_dlg.ui
    crl_info_dlg.ui
    csr_info_dlg.ui
    export_dlg.ui
    get_uri_dlg.ui
    import_dlg.ui
    lcn_info_dlg.ui
    login_dlg.ui
    mainwindow.ui
    make_cert_dlg.ui
    make_cert_profile_dlg.ui
    make_cert_profile_dlg.ui
    make_crl_dlg.ui
    make_crl_profile_dlg.ui
    make_crl_profile_dlg.ui
    make_req_dlg.ui
    new_key_dlg.ui
    pin_dlg.ui
    pri_key_info_dlg.ui
    pub_ldap_dlg.ui
    remote_db_dlg.ui
    renew_cert_dlg.ui
    revoke_cert_dlg.ui
    search_form.ui
    server_status_dlg.ui
    set_pass_dlg.ui
    settings_dlg.ui
    signer_dlg.ui
    stat_form.ui
    statistics_form.ui
    tsp_dlg.ui
    tst_info_dlg.ui
    user_dlg.ui
    make_dn_dlg.ui
)


set(PROJECT_SOURCES
    ${PROJECT_SRC} ${PROJECT_HEADER} ${PROJECT_FORM}
)

set(RESOURCE ${CMAKE_SOURCE_DIR}/certman.qrc)
qt5_add_resources(RESOURCE_ADDED ${RESOURCE})

add_executable(${PROJECT_NAME}
    ${PROJECT_SOURCES}
    ${RESOURCE_ADDED}
    cm.rc
    certman.icns
    CertMan.pro
    pki_srv_dlg.h pki_srv_dlg.cpp pki_srv_dlg.ui
    copy_right_dlg.h copy_right_dlg.cpp copy_right_dlg.ui
    mainwindow2.cpp
    passwd_dlg.cpp passwd_dlg.h passwd_dlg.ui
    new_passwd_dlg.cpp new_passwd_dlg.h new_passwd_dlg.ui
    code_editor.cpp code_editor.h
    ca_man_dlg.h ca_man_dlg.cpp ca_man_dlg.ui
    profile_man_dlg.h profile_man_dlg.cpp profile_man_dlg.ui
)

target_link_options( ${PROJECT_NAME} PRIVATE -mwindows -MD )

target_compile_definitions( ${PROJECT_NAME} PRIVATE USE_CMP USE_SCEP )

if(WIN32)
    include_directories( ../../PKILib
    "c:/msys64/mingw64/include"
    ../../lib/win64/winsparkle/include )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug
        ../../lib/win64/debug/openssl3/lib64
        ../../lib/win64/winsparkle/lib
        ../../lib/win64 )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release
        ../../lib/win64/openssl3/lib64
        ../../lib/win64/winsparkle/lib
        ../../lib/win64 )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Sql
        Qt${QT_VERSION_MAJOR}::Network
        PKILib crypto ssl ltdl ldap lber ws2_32 WinSparkle )

    target_compile_definitions( ${PROJECT_NAME} PRIVATE _AUTO_UPDATE )

elseif(APPLE)
    set(CMAKE_MACOSX_BUNDLE ON)
    set(CMAKE_MACOSX_RPATH ON)

    # The MACOSX_BUNDLE_ICON_FILE variable is added to the Info.plist
    # generated by CMake. This variable contains the .icns file name,
    # without the path.

    # And the following tells CMake where to find and install the file itself.

    set_source_files_properties(certman.icns PROPERTIES MACOSX_PACKAGE_LOCATION Resources )

    set_target_properties( ${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE true
        MACOSX_BUNDLE_ICON_FILE certman.icns
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist )

    include_directories( ../../PKILib
        ../../lib/mac/openssl3/include
        /usr/local/include )

    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug
        ../../lib/mac/debug/openssl3/lib
        /usr/local/lib )
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" )
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Release
        ../../lib/mac/openssl3/lib
        /usr/local/lib )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Sql
        Qt${QT_VERSION_MAJOR}::Network
        PKILib crypto ssl ltdl ldap lber
        "-framework AppKit"
        "-framework Carbon"
        "-framework Foundation"
        "-framework ApplicationServices"
        "-framework Sparkle" )

    target_compile_definitions( ${PROJECT_NAME} PRIVATE _AUTO_UPDATE )

elseif(LINUX)
    include_directories( ../../PKILib
        "/usr/local/include" )

    if(Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Debug
        ../../lib/win64/debug/openssl3/lib64
        "/usr/local/lib" )
    endif()

    if(NOT Debug)
        target_link_directories( ${PROJECT_NAME} PRIVATE
        ../../build-PKILib-Desktop_Qt_5_13_2_GCC_64bit-Release
        ../../lib/win64/openssl3/lib64
        "/usr/local/lib" )
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Sql
        Qt${QT_VERSION_MAJOR}::Network
        PKILib crypto ssl ltdl ldap lber )
endif()

target_compile_definitions( ${PROJECT_NAME} PRIVATE
    CERTMAN_VERSION=${PROJECT_VERSION}
    QT_DEPRECATED_WARNINGS
)


find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets LinguistTools REQUIRED)
set(TS_FILES certman_ko_KR.ts)
#qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})

if(WIN32)
    install( TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin )
elseif(APPLE)
    install( TARGETS ${PROJECT_NAME} BUNDLE DESTINATION . RUNTIME DESTINATION . )
elseif(LINUX)
    install( TARGETS ${PROJECT_NAME} RUNTIME_DESTINATION bin )
endif()
