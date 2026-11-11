file(GLOB LANG_FILES "languages/*.txt")
list(SORT LANG_FILES)

# Watch the languages directory (for added/removed files) and each individual file (for edits):
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "languages" ${LANG_FILES})

# Reorder to put english first
set(LANG_FILES_ORDERED "")
set(ENGLISH_FILE "")
foreach(f IN LISTS LANG_FILES)
    get_filename_component(filename "${f}" NAME_WE)
    if(filename STREQUAL "english")
        set(ENGLISH_FILE "${f}")
    else()
        list(APPEND LANG_FILES_ORDERED "${f}")
    endif()
endforeach()

if(NOT ENGLISH_FILE STREQUAL "")
    set(LANG_FILES "${ENGLISH_FILE}" ${LANG_FILES_ORDERED})
else()
    set(LANG_FILES ${LANG_FILES_ORDERED})
endif()

set(MNEMONIC_SOURCES "")
set(LANG_EXTERNS "")
set(LANG_LIST "")
set(LANG_COUNT 0)

foreach(f IN LISTS LANG_FILES)
    get_filename_component(lang_var "${f}" NAME_WE)
    
    # Read file and split by newline manually to avoid semicolon/parentheses issues
    file(READ "${f}" RAW_CONTENT)
    string(REPLACE "\n" ";" LINES "${RAW_CONTENT}")
    
    list(LENGTH LINES LINE_COUNT)
    # Check if we have exactly 1629 lines. 
    # If the file ends with a newline, file(READ) + string(REPLACE) might produce 1630 elements.
    # We'll normalize this by checking for an empty last element if LINE_COUNT is 1630.
    if(LINE_COUNT EQUAL 1630)
        list(GET LINES 1629 LAST_LINE)
        if(LAST_LINE STREQUAL "")
            list(REMOVE_AT LINES 1629)
            set(LINE_COUNT 1629)
        endif()
    endif()

    if(NOT LINE_COUNT EQUAL 1629)
        message(FATAL_ERROR "Language file ${f} has ${LINE_COUNT} lines, expected 1629.")
    endif()

    list(GET LINES 0 ENGLISH_NAME)
    list(GET LINES 1 NATIVE_NAME)
    list(GET LINES 2 PREFIX_LEN)
    
    set(WORDS_CODE "")
    # Exactly 1626 words starting at index 3.
    foreach(I RANGE 3 1628)
        list(GET LINES ${I} word)
        if(word STREQUAL "")
            message(FATAL_ERROR "Empty word found in ${f} at index ${I}")
        endif()
        if(word MATCHES "[ \t]")
            message(FATAL_ERROR "Word '${word}' in ${f} contains whitespace")
        endif()
        string(APPEND WORDS_CODE "        \"${word}\",\n")
    endforeach()

    set(GENERATED_CPP "${CMAKE_CURRENT_BINARY_DIR}/lang_${lang_var}.cpp")
    # configure_file only rewrites an output whose content changed, so a reconfigure doesn't touch
    # the generated sources (and force them all to recompile) unless a language file changed.
    configure_file(lang.cpp.in "${GENERATED_CPP}" @ONLY)
    list(APPEND MNEMONIC_SOURCES "${GENERATED_CPP}")
    string(APPEND LANG_EXTERNS "extern const Mnemonics ${lang_var};\n")
    string(APPEND LANG_LIST "    &${lang_var},\n")
    math(EXPR LANG_COUNT "${LANG_COUNT} + 1")
endforeach()

set(MASTER_CPP "${CMAKE_CURRENT_BINARY_DIR}/mnemonics_registry.cpp")
configure_file(mnemonics_registry.cpp.in "${MASTER_CPP}" @ONLY)

list(APPEND MNEMONIC_SOURCES "${MASTER_CPP}")

# Add the generated sources to the crypto library
target_sources(crypto PRIVATE ${MNEMONIC_SOURCES} mnemonics.cpp)
