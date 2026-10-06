
# Call as:
#
#     libsession_static_bundle_libs(ARCHIVES_VAR SYSTEM_VAR target [target2 ...])
#
# to walk the link closure of the given targets.  ARCHIVES_VAR is set to every static library in
# it: the archives that combine into the STATIC_BUNDLE libsession-util.a.  SYSTEM_VAR is set to
# everything else the closure links: system libraries such as iconv, Apple frameworks, linker flags
# and imported non-static targets such as Threads::Threads.  None of those can go into an archive,
# so whatever links the bundle has to supply them.
#
# The closure is read from the targets' link properties, so this has to be called after every
# target_link_libraries() it depends on.
function(libsession_static_bundle_libs archives_out system_out)
    set(pending ${ARGN})
    set(visited)
    set(archives)
    set(system)
    while(NOT "${pending}" STREQUAL "")
        list(POP_FRONT pending tgt)
        if(tgt MATCHES "^\\$<LINK_ONLY:(.+)>$")
            set(tgt "${CMAKE_MATCH_1}")
        endif()
        if(NOT TARGET "${tgt}")
            # Silently skipping either of these could drop a library from the bundle, which then
            # only shows up when something links against it.  A `::` name is an imported target
            # created in some subdirectory without GLOBAL, which we cannot see (let alone look
            # inside) from here: find_package() it before calling this.
            if(tgt MATCHES "\\$<")
                message(FATAL_ERROR "Static bundle: don't know how to follow link item ${tgt}")
            endif()
            if(tgt MATCHES "::")
                message(FATAL_ERROR "Static bundle: imported target ${tgt} is not visible here")
            endif()
            list(APPEND system "${tgt}")
            continue()
        endif()
        get_target_property(aliased ${tgt} ALIASED_TARGET)
        if(aliased)
            set(tgt "${aliased}")
        endif()
        if(tgt IN_LIST visited)
            continue()
        endif()
        list(APPEND visited "${tgt}")

        get_target_property(type ${tgt} TYPE)
        get_target_property(imported ${tgt} IMPORTED)
        if(type STREQUAL STATIC_LIBRARY)
            list(APPEND archives "${tgt}")
        elseif(imported)
            # Something the system provides (Threads::Threads).  Linking it by name brings
            # everything it carries, including link options, which this walk does not read.
            list(APPEND system "${tgt}")
            continue()
        endif()

        # An imported target (which is what session-deps produces for each static dependency)
        # carries its dependencies only in INTERFACE_LINK_LIBRARIES; one built here also has its
        # private ones in LINK_LIBRARIES.
        get_target_property(deps ${tgt} INTERFACE_LINK_LIBRARIES)
        if(NOT type STREQUAL INTERFACE_LIBRARY AND NOT imported)
            get_target_property(link_deps ${tgt} LINK_LIBRARIES)
            list(APPEND deps ${link_deps})
        endif()
        # ::@(dir) ... ::@ are cmake's own markers around items that target_link_libraries() added
        # from another directory, not link items themselves.
        list(FILTER deps EXCLUDE REGEX "-NOTFOUND$|^::@")
        list(APPEND pending ${deps})
    endwhile()
    list(REMOVE_DUPLICATES system)
    set(${archives_out} "${archives}" PARENT_SCOPE)
    set(${system_out} "${system}" PARENT_SCOPE)
endfunction()
