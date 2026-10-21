add_subdirectory(Catch2)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions(-DRELEASE_BUILD)
endif()

set(LIB_SESSION_UTESTS_SOURCES
    test_client/attachments.cpp
    test_client/configs.cpp
    test_client/conversation_api.cpp
    test_client/download_cache.cpp
    test_client/profile_pictures.cpp
    test_client/ids_and_schema.cpp
    test_client/interop_and_threading.cpp
    test_client/receiving.cpp
    test_client/replies.cpp
    test_client/requests.cpp
    test_client/sending.cpp
    test_client/volatile.cpp
    test_core_configs.cpp
    test_core_devices.cpp
    test_core_globals.cpp
    test_core_schema.cpp
    test_dm_receive.cpp
    test_dm_send.cpp
    test_attachment_encrypt.cpp
    test_blinding.cpp
    test_bt_merge.cpp
    test_expected.cpp
    test_bugs.cpp
    test_compression.cpp
    test_config_userprofile.cpp
    test_config_user_groups.cpp
    test_configdata.cpp
    test_config_contacts.cpp
    test_config_convo_info_volatile.cpp
    test_config_local.cpp
    test_config_pro.cpp
    test_curve25519.cpp
    test_ed25519.cpp
    test_encrypt.cpp
    test_format.cpp
    test_group_keys.cpp
    test_group_info.cpp
    test_group_members.cpp
    test_hash.cpp
    test_image_jpeg.cpp
    test_image_platform.cpp
    test_image_probe.cpp
    test_image_thumbhash.cpp
    test_image_vips.cpp
    #test_logging.cpp  # Handled separately, see below
    test_multi_encrypt.cpp
    test_mnemonics.cpp
    test_proto.cpp
    test_pro_backend.cpp
    test_random.cpp
    test_session_encrypt.cpp
    test_network_teardown.cpp
    test_swarm_retry.cpp
    test_utils.cpp
    test_session_protocol.cpp
    test_xed25519.cpp
    test_unicode_operations.cpp

    case_logger.cpp
)

list(APPEND LIB_SESSION_UTESTS_SOURCES
    test_backend_session_file_server.cpp
    test_backed_session_open_group_server.cpp
    test_ip_country.cpp
    test_network_swarm.cpp
    test_onionreq.cpp
    test_onion_request_router.cpp
    test_snode_pool.cpp
    test_core_network.cpp
    test_poll.cpp
    test_profile_fetch.cpp
    test_pfs_key_cache.cpp
    test_sqlite_bind.cpp)

add_library(test_libs INTERFACE)

target_link_libraries(test_libs INTERFACE
    libsession::client
    libsession::config
    libsession::core
    libsession::crypto
    sessiondep::nettle
    session::SQLite
    sessiondep::libsodium
    mlkem_native::mlkem768
    nlohmann_json::nlohmann_json
    oxen::logging)

target_link_libraries(test_libs INTERFACE
    libsession::network
    libsession::image
    # The image tests inspect libvips and libheif directly to confirm what libsession::image did.
    sessiondep::vips
    sessiondep::libheif)
if(SESSION_ENABLE_JPEGLI)
    target_compile_definitions(test_libs INTERFACE SESSION_ENABLE_JPEGLI)
endif()

add_executable(testAll main.cpp ${LIB_SESSION_UTESTS_SOURCES})
target_include_directories(testAll PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
add_subdirectory(schema)
target_link_libraries(testAll PRIVATE
    test_libs
    Catch2::Catch2)

option(TEST_PRO_BACKEND_WITH_DEV_SERVER "Run the Pro Backend tests relying on a SESH_PRO_BACKEND_DEV=1 enabled server at the specified string with CURL" OFF)
if (TEST_PRO_BACKEND_WITH_DEV_SERVER)
    find_package(CURL REQUIRED)
    target_link_libraries(testAll PRIVATE CURL::libcurl)
    target_compile_definitions(testAll PRIVATE TEST_PRO_BACKEND_WITH_DEV_SERVER)
endif()


# This one is compiled to a separate binary because it manipulates the logging level and sinks, and
# thus breaks logging in any tests that would run after it if bundled into the main testAll:
add_executable(testLogging test_logging.cpp)
target_link_libraries(testLogging PRIVATE
    test_libs
    Catch2::Catch2WithMain)

# Driven by schema_history_check.sh rather than being a unit test: it needs schemas out of git
# history, since a previous full_schema.sql is the only thing a database can be upgraded *from*.
add_executable(schema-upgrade-check schema_upgrade_check.cpp)
target_link_libraries(schema-upgrade-check PRIVATE
    libsession::client
    test_libs)

if(NOT TARGET check)
    add_custom_target(check
        COMMAND testLogging
        COMMAND testAll
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/schema_history_check.sh" $<TARGET_FILE:schema-upgrade-check>
        DEPENDS schema-upgrade-check)
endif()

option(BUILD_LIVE_TESTS "Build the live testnet integration tests" ON)

if(BUILD_LIVE_TESTS)
    add_executable(testLive
        live/main.cpp
        live/test_swarm.cpp
        live/test_pubkey_xfer.cpp
        live/test_file_transfer.cpp
        live/test_attachment_send.cpp)
    target_link_libraries(testLive PRIVATE
        test_libs
        Catch2::Catch2)
endif()

if(BUILD_LIVE_TESTS)
    add_executable(quic-files EXCLUDE_FROM_ALL quic-files.cpp)
    target_link_libraries(quic-files PRIVATE test_libs)
    target_include_directories(quic-files PRIVATE
        ${CMAKE_SOURCE_DIR}/external/session-router/external/CLI11/include)
endif()

add_executable(swarm-auth-test EXCLUDE_FROM_ALL swarm-auth-test.cpp)
target_link_libraries(swarm-auth-test PRIVATE config)

if(STATIC_BUNDLE)
    add_executable(static-bundle-test static_bundle.cpp)
    target_include_directories(static-bundle-test PUBLIC ../include)
    target_link_libraries(static-bundle-test PRIVATE "${PROJECT_BINARY_DIR}/libsession-util.a" oxenc::oxenc oxen::quic)
    add_dependencies(static-bundle-test session-util)
endif()
