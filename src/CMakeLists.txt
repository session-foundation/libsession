
add_library(common INTERFACE)
target_link_libraries(common INTERFACE
    oxenc::oxenc
    oxen::logging)

target_include_directories(common INTERFACE ../include)
if(WARNINGS_AS_ERRORS)
    target_compile_options(common INTERFACE -Werror)
    message(STATUS "Compiling with fatal warnings (-Werror)")
    if (CMAKE_CXX_COMPILER_ID STREQUAL GNU AND
            CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 11 AND
            CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
        # -Wstringop-overflow triggers (falsely) in protobuf in GCC 11/12/13 so disable it there
        # (fingers crossed for 14).
        message(STATUS "Disabling -Werror for buggy GCC stringop-overflow")
        target_compile_options(common INTERFACE -Wno-error=stringop-overflow)
    endif()
endif()

if(FATAL_MISSING_DECLARATIONS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(common INTERFACE -Werror=missing-declarations)
        message(STATUS "Compiling with -Werror=missing-declarations")
    else()
        message(WARNING "FATAL_MISSING_DECLARATIONS is not supported by this compiler (${CMAKE_CXX_COMPILER_ID}); ignoring")
    endif()
endif()

# -Wunused-parameter isn't in the default warning set (we don't pass -Wextra), so enable it
# explicitly. WARNINGS_AS_ERRORS's -Werror (above) then promotes it to an error.
if(WARN_UNUSED_PARAMETERS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(common INTERFACE -Wunused-parameter)
endif()


set(export_targets)
macro(add_libsession_util_library name)
    add_library(${name} ${ARGN})

    set_target_properties(
        ${name}
        PROPERTIES
        OUTPUT_NAME session-${name}
        SOVERSION ${LIBSESSION_LIBVERSION})

    libsession_static_bundle(${name})

    list(APPEND export_targets ${name})
endmacro()



add_libsession_util_library(util
    file.cpp
    logging.cpp
    util.cpp
)

add_libsession_util_library(crypto
    attachments.cpp
    blinding.cpp
    crypto/ed25519.cpp
    crypto/mlkem768.cpp
    crypto/x25519.cpp
    curve25519.cpp
    hash.cpp
    multi_encrypt.cpp
    random.cpp
    session_encrypt.cpp
    session_protocol.cpp
    sodium_array.cpp
    xed25519.cpp
    xed25519-tweetnacl.cpp
    pro_backend.cpp
    types.cpp
)

add_libsession_util_library(config
    bt_merge.cpp
    config.cpp
    config/base.cpp
    config/community.cpp
    config/contacts.cpp
    config/convo_info_volatile.cpp
    config/encrypt.cpp
    config/error.c
    config/groups/info.cpp
    config/groups/keys.cpp
    config/groups/members.cpp
    config/internal.cpp
    config/local.cpp
    config/protos.cpp
    config/pro.cpp
    config/user_groups.cpp
    config/user_profile.cpp
)



target_link_libraries(util
    PUBLIC
    common
    oxen::logging
    PRIVATE
    sessiondep::libzstd
    sessiondep::simdutf
)

target_link_libraries(crypto
    PUBLIC
    util
    session::secure_buffer
    PRIVATE
    sessiondep::libsodium
    # AES-CBC for legacy attachment decryption, which libsodium has no equivalent of: it exposes
    # AES only as GCM, and only where the hardware supports it.
    sessiondep::nettle
    sessiondep::simdutf
    sessiondep::libutf8proc
    mlkem_native::mlkem768
    nlohmann_json::nlohmann_json
    libsession::protos
)

# libsession "Core" for maintaining persistent Session client state
add_libsession_util_library(core
    core.cpp
    core/component.cpp
    core/configs.cpp
    core/devices.cpp
    core/globals.cpp
    core/link_sas.cpp
    core/pro.cpp
)
add_subdirectory(core/schema)
add_subdirectory(mnemonics)

# Conversation-level data model built on top of core.  The dependency is one-directional by
# design: core neither knows nor links this.
add_libsession_util_library(client
    client/client.cpp
    client/conversation.cpp
    client/download_cache.cpp
    client/conversation_id.cpp
)
add_subdirectory(client/schema)

target_link_libraries(
    client
    PUBLIC
    core
    PRIVATE
    libsession::protos
)

target_link_libraries(
    core
    PUBLIC
    crypto
    # core.hpp holds a sqlite::Database by value and takes DatabaseOptions in its constructor, so
    # consumers need the SQLiteCpp headers.
    session::SQLite
    # Core owns the account's config objects and hands them out by reference, so a consumer that
    # reads one calls into config itself.
    config
    PRIVATE
    libsession::protos
    sessiondep::libsodium
    nlohmann_json::nlohmann_json
    mlkem_native::mlkem768
    oxen::quic
)

target_link_libraries(config
    PUBLIC
    crypto
    libsession::protos
    PRIVATE
    sessiondep::libsodium
)

session_dep(libevent_core 2.1)

add_libsession_util_library(network
    onionreq/builder.cpp
    onionreq/hop_encryption.cpp
    onionreq/parser.cpp
    onionreq/response_parser.cpp
    network/ip_country/lookup.cpp
    network/key_types.cpp
    network/network_config.cpp
    network/request_queue.cpp
    network/service_node.cpp
    network/session_network_internal.cpp
    network/session_network_types.cpp
    network/session_network.cpp
    network/snode_pool.cpp
    network/swarm.cpp
    network/backends/quic_file_client.cpp
    network/backends/session_file_server.cpp
    network/backends/session_open_group_server.cpp
    network/transport/quic_transport.cpp
    network/routing/direct_router.cpp
    network/routing/onion_request_router.cpp
)

target_link_libraries(network
    PUBLIC
    crypto
    oxen::quic
    # service_node.hpp declares `service_node::from_json(nlohmann::json)`, so anything including it
    # -- which core.hpp does, and so anything using core -- needs the json headers.
    nlohmann_json::nlohmann_json
    PRIVATE
    sessiondep::libsodium
    sessiondep::nettle
    date::date
    sessiondep::libevent_core
)

# The two databases define the same accessors, so the lookup code is identical either way and only
# the table it searches differs; see src/network/ip_country/data.hpp.
if(WITH_IP_GEOLOCATION)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/network/ip_country/data.cpp")
        # Generating it needs a ~4.5MB download, so it is neither committed nor fetched during a
        # build: ask for it explicitly, once, and it stays until the next refresh.
        message(FATAL_ERROR
            "WITH_IP_GEOLOCATION is enabled but the database has not been generated yet.  Run\n"
            "    ${PROJECT_SOURCE_DIR}/utils/update-ip-country-db.py\n"
            "to download a DB-IP Lite release and generate it, then re-run cmake.")
    endif()
    target_sources(network PRIVATE network/ip_country/data.cpp)
else()
    target_sources(network PRIVATE network/ip_country/no_data.cpp)
endif()

if(ENABLE_NETWORKING_SROUTER)
    target_sources(network
        PRIVATE
        network/routing/session_router_router.cpp)
    target_link_libraries(network PUBLIC session-router::core)
    target_compile_definitions(network PUBLIC ENABLE_NETWORKING_SROUTER)
endif()

if (BUILD_STATIC_DEPS)
    target_include_directories(network PUBLIC ${CMAKE_BINARY_DIR}/static-deps/include)
endif()

# core's public headers expose network::Network and it constructs network::Request, so it
# depends on the network target (defined after core above).
target_link_libraries(core PUBLIC network)

add_libsession_util_library(image
    image/thumbhash.cpp
    image/vips.cpp
)
target_link_libraries(image
    PUBLIC
    util
    PRIVATE
    sessiondep::vips
)

if(WARNINGS_AS_ERRORS AND NOT USE_LTO AND CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION MATCHES "^11\\.")
    # GCC 11 has an overzealous (and false) stringop-overread warning, but only when LTO is off.
    # Um, yeah.
    target_compile_options(config PUBLIC -Wno-error=stringop-overread)
endif()

# GCC's stringop overflow and overread warnings are very buggy, producing false positives for all
# sorts of valid things, so make sure we don't have -Werror for them.  We cap this check for now at
# 15 (where these still occur in the latest gcc snapshot) with the vain hope that maybe they'll get
# fixed for gcc 16.
if(WARNINGS_AS_ERRORS AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
        CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 12.0.0 AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16.0.0)
    target_compile_options(crypto PUBLIC -Wno-error=stringop-overflow -Wno-error=stringop-overread)
endif()

if(LIBSESSION_UTIL_VERSIONTAG)
    set(PROJECT_VERSION_TAG "${LIBSESSION_UTIL_VERSIONTAG}")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/version.c")
else()
    find_package(Git)
    if(EXISTS "${PROJECT_SOURCE_DIR}/.git/index" AND GIT_FOUND)
        add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/version.c"
            COMMAND
            "${CMAKE_COMMAND}"
            "-DGIT=${GIT_EXECUTABLE}"
            "-DPROJECT_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}"
            "-DPROJECT_VERSION_MINOR=${PROJECT_VERSION_MINOR}"
            "-DPROJECT_VERSION_PATCH=${PROJECT_VERSION_PATCH}"
            "-DSRC=${CMAKE_CURRENT_SOURCE_DIR}/version.c.in"
            "-DDEST=${CMAKE_CURRENT_BINARY_DIR}/version.c"
            "-P" "${PROJECT_SOURCE_DIR}/cmake/GenVersion.cmake"
            DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/version.c.in"
            "${PROJECT_SOURCE_DIR}/.git/index")
    else()
        message(STATUS "Git was not found or this is not a git checkout. Setting version tag to 'unknown'")
        set(PROJECT_VERSION_TAG "nogit")
        configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/version.c")
    endif()
endif()
add_library(version STATIC version.c)
libsession_static_bundle(version)
target_include_directories(version PRIVATE ../include)
target_link_libraries(common INTERFACE version)


foreach(tgt ${export_targets})
    add_library("libsession::${tgt}" ALIAS "${tgt}")
endforeach()

list(APPEND libsession_export_targets ${export_targets})
set(libsession_export_targets "${libsession_export_targets}" PARENT_SCOPE)
