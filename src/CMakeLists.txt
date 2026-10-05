
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
    curve25519.cpp
    ed25519.cpp
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
    fields.cpp
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
    PRIVATE
    sessiondep::libsodium
    nlohmann_json::nlohmann_json
    libsession::protos
)

target_link_libraries(config
    PUBLIC
    crypto
    libsession::protos
    PRIVATE
    sessiondep::libsodium
)

if(ENABLE_NETWORKING)
    session_dep(libevent_core 2.1)

    add_libsession_util_library(network
        onionreq/builder.cpp
        onionreq/hop_encryption.cpp
        onionreq/parser.cpp
        onionreq/response_parser.cpp
        network/key_types.cpp
        network/network_config.cpp
        network/request_queue.cpp
        network/service_node.cpp
        network/session_network_internal.cpp
        network/session_network_types.cpp
        network/session_network.cpp
        network/snode_pool.cpp
        network/swarm.cpp
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
        PRIVATE
        nlohmann_json::nlohmann_json
        sessiondep::libsodium
        sessiondep::nettle
        date::date
        sessiondep::libevent_core
    )

    if(ENABLE_NETWORKING_SROUTER)
        target_sources(network
            PRIVATE
            network/routing/session_router_router.cpp)
        target_link_libraries(network PUBLIC session-router::core)
    endif()

    if (BUILD_STATIC_DEPS)
        target_include_directories(network PUBLIC ${CMAKE_BINARY_DIR}/static-deps/include)
    endif()
endif()

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
