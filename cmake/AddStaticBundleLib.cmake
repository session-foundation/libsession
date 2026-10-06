
set(LIBSESSION_STATIC_BUNDLE_LIBS "" CACHE INTERNAL "list of libs to go into the static bundle lib")

function(_libsession_static_bundle_append tgt)
    list(APPEND LIBSESSION_STATIC_BUNDLE_LIBS "${tgt}")
    set(LIBSESSION_STATIC_BUNDLE_LIBS "${LIBSESSION_STATIC_BUNDLE_LIBS}" CACHE INTERNAL "")
endfunction()

# Call as:
#
#     libsession_static_bundle(target [target2 ...])
#
# to append the given target(s) to the list of libraries that will be combined to make the static
# bundled libsession-util.a.
function(libsession_static_bundle)
    foreach(tgt IN LISTS ARGN)
        if(TARGET "${tgt}" AND NOT "${tgt}" IN_LIST LIBSESSION_STATIC_BUNDLE_LIBS)
            get_target_property(tgt_type ${tgt} TYPE)
            
            if(tgt_type STREQUAL STATIC_LIBRARY)
                message(STATUS "Adding ${tgt} to libsession-util bundled library list")
                _libsession_static_bundle_append("${tgt}")
            endif()

            if(tgt_type STREQUAL INTERFACE_LIBRARY)
                get_target_property(tgt_link_deps ${tgt} INTERFACE_LINK_LIBRARIES)
            else()
                get_target_property(tgt_link_deps ${tgt} LINK_LIBRARIES)
            endif()

            if(tgt_link_deps)
                libsession_static_bundle(${tgt_link_deps})
            endif()
        endif()
    endforeach()
endfunction()

function(_libsession_static_bundle_walk tgt)
    if(tgt MATCHES "^\\$<LINK_ONLY:(.+)>$")
        set(tgt "${CMAKE_MATCH_1}")
    endif()
    if(NOT TARGET "${tgt}")
        return()
    endif()
    get_target_property(aliased ${tgt} ALIASED_TARGET)
    if(aliased)
        set(tgt "${aliased}")
    endif()

    get_property(visited GLOBAL PROPERTY _libsession_static_bundle_visited)
    if("${tgt}" IN_LIST visited)
        return()
    endif()
    set_property(GLOBAL APPEND PROPERTY _libsession_static_bundle_visited "${tgt}")

    get_target_property(tgt_type ${tgt} TYPE)
    if(tgt_type STREQUAL STATIC_LIBRARY)
        # The list can hold alias names (eg. protobuf::libprotobuf-lite), so compare what they resolve to
        set(already_bundled FALSE)
        foreach(bundled IN LISTS LIBSESSION_STATIC_BUNDLE_LIBS)
            get_target_property(bundled_aliased ${bundled} ALIASED_TARGET)
            if(bundled STREQUAL tgt OR bundled_aliased STREQUAL tgt)
                set(already_bundled TRUE)
                break()
            endif()
        endforeach()
        if(NOT already_bundled)
            message(STATUS "Adding ${tgt} to libsession-util bundled library list")
            _libsession_static_bundle_append("${tgt}")
        endif()
    endif()

    # An imported target (which is what session-deps produces for each static dependency) carries
    # its own dependencies only in INTERFACE_LINK_LIBRARIES; a target built here has them in
    # LINK_LIBRARIES.
    get_target_property(deps ${tgt} INTERFACE_LINK_LIBRARIES)
    get_target_property(imported ${tgt} IMPORTED)
    if(NOT tgt_type STREQUAL INTERFACE_LIBRARY AND NOT imported)
        get_target_property(link_deps ${tgt} LINK_LIBRARIES)
        list(APPEND deps ${link_deps})
    endif()
    foreach(dep IN LISTS deps)
        _libsession_static_bundle_walk("${dep}")
    endforeach()
endfunction()

# Adds every static library that the already-registered targets link against, transitively.  Call
# once all targets have their links set up: libsession_static_bundle() runs as each library is
# created, before its target_link_libraries(), so on its own it never sees a library's dependencies.
function(libsession_static_bundle_resolve)
    set_property(GLOBAL PROPERTY _libsession_static_bundle_visited "")
    foreach(tgt IN LISTS LIBSESSION_STATIC_BUNDLE_LIBS)
        _libsession_static_bundle_walk("${tgt}")
    endforeach()
endfunction()
