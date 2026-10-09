add_subdirectory(Catch2)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_definitions(-DRELEASE_BUILD)
endif()

set(LIB_SESSION_UTESTS_SOURCES
    test_attachment_encrypt.cpp
    test_blinding.cpp
    test_bt_merge.cpp
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
    test_group_keys.cpp
    test_group_info.cpp
    test_group_members.cpp
    test_hash.cpp
    #test_logging.cpp  # Handled separately, see below
    test_multi_encrypt.cpp
    test_proto.cpp
    test_pro_backend.cpp
    test_random.cpp
    test_session_encrypt.cpp
    test_utils.cpp
    test_session_protocol.cpp
    test_xed25519.cpp
    test_unicode_operations.cpp
    test_backend_session_file_server.cpp
    test_backed_session_open_group_server.cpp

    case_logger.cpp
)

if(ENABLE_NETWORKING)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_network_config.cpp)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_network_swarm.cpp)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_onionreq.cpp)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_onion_request_router.cpp)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_quic_transport.cpp)
    list(APPEND LIB_SESSION_UTESTS_SOURCES test_snode_pool.cpp)
endif()

add_library(test_libs INTERFACE)

target_link_libraries(test_libs INTERFACE
    libsession::config
    sessiondep::libsodium
    nlohmann_json::nlohmann_json
    oxen::logging)

if (ENABLE_NETWORKING)
    target_link_libraries(test_libs INTERFACE libsession::network)
else()
    target_compile_definitions(test_libs INTERFACE DISABLE_NETWORKING)
endif()

add_executable(testAll main.cpp ${LIB_SESSION_UTESTS_SOURCES})
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

if(NOT TARGET check)
    add_custom_target(check
        COMMAND testLogging
        COMMAND testAll)
endif()

add_executable(swarm-auth-test EXCLUDE_FROM_ALL swarm-auth-test.cpp)
target_link_libraries(swarm-auth-test PRIVATE config)
