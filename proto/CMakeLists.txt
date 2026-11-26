
add_library(protos
    SessionProtos.pb.cc
    WebSocketResources.pb.cc
    debug_print.cpp)
target_include_directories(protos PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# `common` is for debug_print.cpp, which needs fmt and oxenc to render; PRIVATE because nothing
# about the generated message classes exposes either.
target_link_libraries(protos PUBLIC protobuf::libprotobuf-lite PRIVATE common)
set_target_properties(
    protos PROPERTIES
    OUTPUT_NAME session-protos
    SOVERSION ${LIBSESSION_LIBVERSION})

# -Wunused-parameter triggers in the protobuf dependency
message(STATUS "Disabling -Werror for proto unused-parameter")

if (MSVC)
else()
    target_compile_options(protos PUBLIC -Wno-error=unused-parameter)
endif()

add_library(libsession::protos ALIAS protos)
list(APPEND libsession_export_targets protos)
set(libsession_export_targets "${libsession_export_targets}" PARENT_SCOPE)


# Regenerates both the protobuf classes and the text dumper built on them.  They come from the same
# descriptors and are checked in together, which is what keeps the dumper from falling behind the
# schema -- it has to be generated, because LITE_RUNTIME leaves the classes with no reflection for a
# TextFormat printer to use.  Needs python3-protobuf, and only when run.
add_custom_target(regen-protobuf
    COMMAND protoc --cpp_out=. SessionProtos.proto WebSocketResources.proto
    COMMAND sh -c "protoc --descriptor_set_out=/dev/stdout SessionProtos.proto WebSocketResources.proto | ./gen_debug_print.py ."
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
