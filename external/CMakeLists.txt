include(../cmake/session-deps/Deps.cmake)

message(STATUS "Checking submodules")
check_submodule(ios-cmake)
check_submodule(session-router external/nlohmann external/oxen-libquic)
# check_submodule's extra arguments are resolved as gitlinks of the first argument's repo, and it
# only recurses one level, so anything deeper needs its own call rooted at the repo that records it:
# oxen-encoding and oxen-logging belong to oxen-libquic, and fmt/spdlog to oxen-logging.
set(libquic_dir "${CMAKE_CURRENT_SOURCE_DIR}/session-router/external/oxen-libquic")
check_submodule(external/oxen-encoding WORKING_DIRECTORY "${libquic_dir}")
check_submodule(external/oxen-logging fmt spdlog WORKING_DIRECTORY "${libquic_dir}")
check_submodule(protobuf)
check_submodule(date)
check_submodule(session-sqlite SQLiteCpp cmake/session-deps)

# 1.2.2+ required for logging sink removal support
set(OXEN_LOGGING_MIN_VERSION 1.2.2 CACHE STRING "")

if(NOT BUILD_STATIC_DEPS AND NOT FORCE_ALL_SUBMODULES)
  find_package(PkgConfig REQUIRED)
endif()

function(add_static_subdirectory dir)
    set(BUILD_SHARED_LIBS OFF)
    add_subdirectory(${dir} ${ARGN})
endfunction()

session_dep(libsodium 1.0.21)
libsession_static_bundle(sessiondep::libsodium)

if(NOT TARGET oxenc::oxenc)
    set(OXENC_BUILD_TESTS OFF CACHE BOOL "")
    set(OXENC_BUILD_DOCS OFF CACHE BOOL "")
    sessiondep_or_submodule(liboxenc 1.6.0 session-router/external/oxen-libquic/external/oxen-encoding oxenc::oxenc)
endif()

if(ENABLE_NETWORKING_SROUTER)
    set(SROUTER_FULL OFF CACHE BOOL "")
    set(SROUTER_DAEMON OFF CACHE BOOL "")
    set(SROUTER_NATIVE_BUILD OFF CACHE BOOL "")
    set(SROUTER_JEMALLOC OFF CACHE BOOL "")

    add_static_subdirectory(session-router EXCLUDE_FROM_ALL)
    libsession_static_bundle(session-router::core)
endif()

# The network library always needs oxen::quic.  When session-router is built (SROUTER, above) it
# provides oxen::quic transitively; otherwise pull in oxen-libquic on its own.
if(NOT TARGET oxen::quic)
    set(LIBQUIC_BUILD_TESTS OFF CACHE BOOL "")
    sessiondep_or_submodule(liboxenquic 1.12.0 session-router/external/oxen-libquic oxen::quic)
endif()

if(NOT TARGET oxen::logging)
    # oxen-logging can't go through sessiondep_or_submodule: its public headers expose fmt types and
    # a system liboxen-logging's .pc doesn't pull in fmt/spdlog, so consumers must add them
    # explicitly.  oxen-logging ships a cmake/load.cmake that resolves oxen::logging for us -- either
    # a system liboxen-logging bundled with suitable fmt/spdlog targets, or the submodule (which
    # builds its own fmt/spdlog).  This is the same loader oxen-libquic uses.  We just force the
    # submodule path when our other deps would also prefer submodules over system libs.
    option(DEPS_FORCE_liboxen-logging_SUBMODULE "force using liboxen-logging submodule" OFF)
    if(BUILD_STATIC_DEPS OR DEPS_FORCE_SUBMODULE OR DEPS_FORCE_liboxen-logging_SUBMODULE)
        set(OXEN_LOGGING_FORCE_SUBMODULES ON)
    endif()
    include(session-router/external/oxen-libquic/external/oxen-logging/cmake/load.cmake)
endif()



if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
set(deps_CFLAGS "-O2")

if(IPO_ENABLED)
  set(deps_CFLAGS "${deps_CFLAGS} -flto")
endif()

if(APPLE)
    foreach(lang C CXX)
        string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT} ${CMAKE_${lang}_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")
        foreach(arch ${CMAKE_OSX_ARCHITECTURES})
            string(APPEND deps_${lang}FLAGS " -arch ${arch}")
        endforeach()
    endforeach()
endif()

set(protobuf_VERBOSE ON CACHE BOOL "" FORCE)
set(protobuf_INSTALL ON CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBPROTOC OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_ABSL_PROVIDER "module" CACHE STRING "" FORCE)
set(protobuf_BUILD_PROTOC_BINARIES OFF CACHE BOOL "")
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)
sessiondep_or_submodule(protobuf-lite 3.21 protobuf protobuf::libprotobuf-lite)


# Force a static libzstd: we want semi-stable compressed output, which means we want all session
# clients to use the same version (where that is guaranteed) as much as possible, so that duplicate
# configs get deduplicated at the swarm.
set(BUILD_STATIC_libzstd ON CACHE BOOL "" FORCE)
session_dep(libzstd 1.5)
libsession_static_bundle(sessiondep::libzstd)

# TODO FIXME: integrate this with the updated networking PR, which will end up right about here when
# merging.  This can basically just get deleted once we are always building session-router.
if(NOT TARGET mlkem_native::mlkem768)
    file(GLOB_RECURSE mlkem_sources
        session-router/external/mlkem-native/mlkem/src/*.c
        session-router/external/mlkem-native/mlkem/src/*.S)

    add_library(mlkem_native768 STATIC ${mlkem_sources})

    target_compile_definitions(mlkem_native768 PUBLIC
        MLK_CONFIG_NO_RANDOMIZED_API
        MLK_CONFIG_PARAMETER_SET=768
        MLK_CONFIG_NAMESPACE_PREFIX=sr_mlkem768
        MLK_CONFIG_NO_SUPERCOP
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
    )

    target_include_directories(mlkem_native768 PUBLIC session-router/external/mlkem-native/mlkem)

    add_library(mlkem_native::mlkem768 ALIAS mlkem_native768)
endif()

if(NOT TARGET nlohmann_json::nlohmann_json)
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    set(JSON_Install ON CACHE INTERNAL "") # Required to export targets that we use
    sessiondep_or_submodule(nlohmann_json 3.7.0 session-router/external/nlohmann nlohmann_json::nlohmann_json)
endif()


session_dep(simdutf 7)
libsession_static_bundle(sessiondep::simdutf)


add_subdirectory(session-sqlite)


# We need Howard Hinnant's header-only date library for now because the STL implementation of
# std::chrono::parse() is spotty or broken on:
# - Apple.  libc++ date parsing is only available when on XCode 16.3+ *and* targetting macOS 15+.
# - gcc before 13.
# - clang+libc++ before llvm-19.  (Real 19, not Apple's idiotic PR renumbering).
#
# On the plus side, this is header-only so we don't actually compile anything extra if we don't
# actually use it.
add_subdirectory(date)
