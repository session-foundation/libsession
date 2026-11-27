#pragma once

#include <fmt/format.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <chrono>
#include <concepts>
#include <nlohmann/json.hpp>
#include <optional>
#include <session/parse_error.hpp>
#include <session/types.hpp>
#include <span>
#include <string_view>
#include <type_traits>

namespace session::json {

// A T that is carried on the wire as an integer count of seconds: either a duration (seconds) or a
// system-clock time point at second granularity (sys_seconds). require<T>/maybe<T> read
// the integer and wrap it, so a call site never repeats `sys_seconds{seconds{get<int64_t>()}}`.
template <typename T>
concept wire_seconds =
        std::same_as<T, std::chrono::seconds> || std::same_as<T, std::chrono::sys_seconds>;

// Whether the JSON value `v` holds a T, paired with a human name for the type (used in the error
// message on a mismatch). Single source of truth so require and maybe cannot drift on
// what counts as a valid T.
template <typename T>
std::pair<bool, std::string_view> is(const nlohmann::json& v) {
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
    else if constexpr (is_scoped_enum_v<T>)
        // A scoped enum reads as its underlying integer -- nlohmann's default serializer converts
        // through the underlying type (extract's get_to) -- so callers can request the enum
        // directly rather than reading an integer and casting. No caller does today: this arrived
        // for the proof `version` read, which no longer exists.
        //
        // Scoped only: an unscoped enum converts to its underlying integer by itself, so it needs
        // nothing from here and would be better served by whatever an integer gets.
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
T extract(const nlohmann::json& v) {
    if constexpr (wire_seconds<T>)
        return T{std::chrono::seconds{v.template get<int64_t>()}};
    else {
        T result = {};
        v.get_to(result);
        return result;
    }
}

// Parse `input` as JSON, throwing parse_error (not a nlohmann exception) if it is not valid JSON.
inline nlohmann::json parse(std::string_view input) {
    try {
        return nlohmann::json::parse(input);
    } catch (const std::exception& e) {
        throw parse_error{fmt::format("Invalid JSON received, parse failed: {}", e.what())};
    }
}

// Reads a required field: throws parse_error_missing if absent, parse_error_type if the wrong type.
template <typename T>
T require(const nlohmann::json& j, std::string_view key) {
    auto it = j.find(key);
    if (it == j.end())
        throw parse_error_missing{key};
    if (auto [ok, type] = is<T>(*it); !ok)
        throw parse_error_type{key, type, it->dump(1)};
    return extract<T>(*it);
}

// Reads an optional field: a missing key or a wrong-typed value both yield nullopt (rather than
// throwing) -- for advisory fields a caller should read leniently and skip when absent.
template <typename T>
std::optional<T> maybe(const nlohmann::json& j, std::string_view key) {
    auto it = j.find(key);
    if (it == j.end() || !is<T>(*it).first)
        return std::nullopt;
    return extract<T>(*it);
}

// Reads a fixed-length binary value (a pubkey, a signature, a tag) that the wire carries either
// hex- or base64-encoded, filling `dest` exactly.  `dest.size()` is the expected byte length, and
// the encoding is identified from the encoded length alone -- no sniffing of the alphabet, which
// cannot distinguish the two in general (any hex string is also valid base64).
//
// The destination must be a fixed-size byte buffer (a std::array, a C array, or an already
// fixed-extent span) of at least 5 bytes: below that the encodings collide in length and cannot be
// told apart, so the requirement is enforced at compile time.  For 1 byte hex and unpadded base64
// are both 2 chars, for 2 bytes hex and padded base64 are both 4, and for 4 bytes both are 8.  From
// 5 bytes up hex (2N) is strictly longer than padded base64 (4*ceil(N/3) <= (4N+8)/3) and than
// unpadded (ceil(4N/3) <= (4N+2)/3), so the three lengths are always distinct.
template <typename Dest>
    requires requires(Dest& d) { std::span{d}; }
inline void require_binary(const nlohmann::json& j, std::string_view key, Dest& dest_) {
    std::span dest{dest_};
    using D = decltype(dest);
    static_assert(
            std::same_as<typename D::element_type, std::byte>,
            "require_binary writes into a std::byte buffer");
    static_assert(
            D::extent != std::dynamic_extent,
            "require_binary needs a fixed-size destination: the byte length is what selects the "
            "encoding");
    static_assert(
            D::extent >= 5,
            "require_binary cannot disambiguate hex from base64 below 5 bytes (at 1, 2 and 4 bytes "
            "the encoded lengths coincide)");

    auto enc = require<std::string_view>(j, key);

    const auto hex_size = oxenc::to_hex_size(dest.size());
    const auto b64_padded = oxenc::to_base64_size(dest.size(), true);
    const auto b64_unpadded = oxenc::to_base64_size(dest.size(), false);

    if (enc.size() == hex_size) {
        if (!oxenc::is_hex(enc))
            throw session::parse_error_key{
                    key, fmt::format("Key value ({}) was not valid hex: '{}'", key, enc)};
        oxenc::from_hex(enc.begin(), enc.end(), dest.begin());
    } else if (enc.size() == b64_padded || enc.size() == b64_unpadded) {
        if (!oxenc::is_base64(enc))
            throw session::parse_error_key{
                    key, fmt::format("Key value ({}) was not valid base64: '{}'", key, enc)};
        oxenc::from_base64(enc.begin(), enc.end(), dest.begin());
    } else
        throw session::parse_error_key{
                key,
                fmt::format(
                        "Key value ({}) was not a {}-byte value: expected {} hex chars or {}/{} "
                        "base64 chars, got {}",
                        key,
                        dest.size(),
                        hex_size,
                        b64_unpadded,
                        b64_padded,
                        enc.size())};
}

}  // namespace session::json
