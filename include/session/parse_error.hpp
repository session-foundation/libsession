#pragma once

#include <fmt/core.h>

#include <stdexcept>
#include <string>
#include <string_view>

namespace session {

/// Thrown by the parse_* helpers when serialized input (a backend JSON reply, onion-request
/// metadata, a service node description, ...) cannot be understood: malformed JSON, a missing or
/// wrong-typed field, an unrecognized envelope status, or bad hex. This is distinct from a
/// well-formed backend *failure* (an envelope carrying a "fail"/"error" status + error_code), which
/// is not a parse error: it is returned normally with the status/error fields populated.
struct parse_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// A parse failure attributable to a specific field, whose name is carried in `key` (rather than
/// being recoverable only by scraping `what()`).
struct parse_error_key : parse_error {
    std::string key;
    parse_error_key(std::string_view key, std::string_view msg) :
            parse_error{std::string{msg}}, key{key} {}
};

/// A required field was absent.
struct parse_error_missing : parse_error_key {
    explicit parse_error_missing(std::string_view key) :
            parse_error_key{key, fmt::format("Key '{}' is missing", key)} {}
};

/// A field was present but held the wrong type; `expected` names the type that was wanted and
/// `found` is a short rendering of the value that was there instead.
struct parse_error_type : parse_error_key {
    parse_error_type(std::string_view key, std::string_view expected, std::string_view found) :
            parse_error_key{
                    key, fmt::format("Key value ({}, {}) was not {}", key, found, expected)} {}
};

}  // namespace session
