#pragma once

#include <fmt/core.h>
#include <oxenc/hex.h>

#include <chrono>
#include <concepts>
#include <nlohmann/json.hpp>
#include <optional>
#include <session/parse_error.hpp>
#include <session/types.hpp>
#include <string_view>
#include <type_traits>

namespace session::detail {

// A T that is carried on the wire as an integer count of seconds: either a duration (seconds) or a
// system-clock time point at second granularity (sys_seconds). json_require<T>/json_maybe<T> read
// the integer and wrap it, so a call site never repeats `sys_seconds{seconds{get<int64_t>()}}`.
template <typename T>
concept wire_seconds =
        std::same_as<T, std::chrono::seconds> || std::same_as<T, std::chrono::sys_seconds>;

// Whether the JSON value `v` holds a T, paired with a human name for the type (used in the error
// message on a mismatch). Single source of truth so json_require and json_maybe cannot drift on
// what counts as a valid T.
template <typename T>
std::pair<bool, std::string_view> json_is(const nlohmann::json& v) {
    if constexpr (wire_seconds<T>)
        // Integer seconds on the wire; reject a fractional value rather than truncating it.
        return {v.is_number_integer(), "an integer"};
    else if constexpr (std::floating_point<T>)
        // An integer is a valid float, so accept any number: is_number_float() would reject it.
        return {v.is_number(), "a number"};
    else if constexpr (std::same_as<T, bool>)
        return {v.is_boolean(), "a boolean"};
    else if constexpr (std::integral<T>)
        // is_number_integer() (not is_number()) so a fractional value is rejected, not truncated.
        return {v.is_number_integer(), "an integer"};
    else if constexpr (std::is_enum_v<T>)
        // A (scoped) enum reads as its underlying integer -- nlohmann's default serializer converts
        // through the underlying type (json_extract's get_to) -- so callers can request the enum
        // directly rather than reading an integer and casting. No caller does today: this arrived
        // for the proof `version` read, which no longer exists.
        return {v.is_number_integer(), "an integer"};
    else if constexpr (is_one_of<T, std::string, std::string_view>)
        return {v.is_string(), "a string"};
    else if constexpr (std::same_as<T, nlohmann::json::array_t>)
        return {v.is_array(), "an array"};
    else {
        static_assert(std::same_as<T, nlohmann::json::object_t>);
        return {v.is_object(), "an object"};
    }
}

// Extracts an already-type-validated value as T, applying the seconds-wrapping for wire_seconds.
template <typename T>
T json_extract(const nlohmann::json& v) {
    if constexpr (wire_seconds<T>)
        return T{std::chrono::seconds{v.template get<int64_t>()}};
    else {
        T result = {};
        v.get_to(result);
        return result;
    }
}

// Parse `input` as JSON, throwing parse_error (not a nlohmann exception) if it is not valid JSON.
inline nlohmann::json json_parse(std::string_view input) {
    try {
        return nlohmann::json::parse(input);
    } catch (const std::exception& e) {
        throw parse_error{fmt::format("Invalid JSON received, parse failed: {}", e.what())};
    }
}

// Reads a required field: throws parse_error_missing if absent, parse_error_type if the wrong type.
template <typename T>
T json_require(const nlohmann::json& j, std::string_view key) {
    auto it = j.find(key);
    if (it == j.end())
        throw parse_error_missing{key};
    if (auto [ok, type] = json_is<T>(*it); !ok)
        throw parse_error_type{key, type, it->dump(1)};
    return json_extract<T>(*it);
}

// Reads an optional field: a missing key or a wrong-typed value both yield nullopt (rather than
// throwing) -- for advisory fields a caller should read leniently and skip when absent.
template <typename T>
std::optional<T> json_maybe(const nlohmann::json& j, std::string_view key) {
    auto it = j.find(key);
    if (it == j.end() || !json_is<T>(*it).first)
        return std::nullopt;
    return json_extract<T>(*it);
}

inline void json_require_hex(
        const nlohmann::json& j, std::string_view key, std::span<uint8_t> dest) {
    auto hex = json_require<std::string_view>(j, key);
    if (hex.starts_with("0X") || hex.starts_with("0x"))
        hex = hex.substr(2);

    size_t hex_avail = dest.size() * 2;
    if (hex.size() != hex_avail)
        throw session::parse_error_key{
                key,
                fmt::format(
                        "Hex -> bytes failed ({}, {}). {} hex chars capacity (requires {})",
                        key,
                        hex,
                        hex_avail,
                        hex.size())};

    if (!oxenc::is_hex(hex))
        throw session::parse_error_key{
                key, fmt::format("Key value string was not hex: '{}': '{}'", key, hex)};
    oxenc::from_hex(hex.begin(), hex.end(), dest.begin());
}

}  // namespace session::detail
