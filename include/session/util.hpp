#pragma once

#include <oxenc/common.h>

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#ifndef _WIN32
extern "C" {
#include <sys/resource.h>
}
#endif

#include "types.hpp"

namespace session {

using namespace oxenc;

// Helper functions to convert to/from spans
template <oxenc::basic_char OutChar = unsigned char, oxenc::basic_char InChar, size_t Extent>
inline std::span<const OutChar, Extent> as_span(std::span<const InChar, Extent> sp) {
    return std::span<const OutChar, Extent>{reinterpret_cast<const OutChar*>(sp.data()), sp.size()};
}
template <oxenc::basic_char OutChar = unsigned char, oxenc::basic_char InChar, size_t Extent>
inline std::span<OutChar, Extent> as_span(std::span<InChar, Extent> sp) {
    return std::span<OutChar, Extent>{reinterpret_cast<OutChar*>(sp.data()), sp.size()};
}

template <typename OutChar = unsigned char, oxenc::bt_input_string T>
inline std::span<const OutChar> to_span(const T& c) {
    return {reinterpret_cast<const OutChar*>(c.data()), c.size()};
}

template <typename OutChar = unsigned char, std::size_t N>
inline std::span<const OutChar> to_span(const char (&literal)[N]) {
    return {reinterpret_cast<const OutChar*>(literal), N - 1};
}

template <typename OutChar = unsigned char, typename Container>
    requires(!oxenc::bt_input_string<Container>)
inline std::span<const OutChar> to_span(const Container& c) {
    return {reinterpret_cast<const OutChar*>(c.data()), c.size()};
}

// Helper functions to convert container types
template <typename OutContainer, typename InContainer>
inline OutContainer convert(const InContainer& in) {
    using out_value_type = typename OutContainer::value_type;
    auto begin = reinterpret_cast<const out_value_type*>(in.data());
    return OutContainer(begin, begin + in.size());
}

template <typename OutChar = unsigned char, typename InChar>
inline std::vector<OutChar> to_vector(std::span<const InChar> sp) {
    return convert<std::vector<OutChar>>(sp);
}

template <typename OutChar = unsigned char, oxenc::bt_input_string T>
inline std::vector<OutChar> to_vector(const T& c) {
    return convert<std::vector<OutChar>>(to_span(c));
}

template <typename OutChar = unsigned char, typename InChar, std::size_t N>
inline std::vector<OutChar> to_vector(const std::array<InChar, N>& arr) {
    return convert<std::vector<OutChar>>(arr);
}

template <typename OutChar = unsigned char, typename Container>
    requires(!oxenc::bt_input_string<Container>)
inline std::vector<OutChar> to_vector(const Container& c) {
    return convert<std::vector<OutChar>>(to_span(c));
}

template <std::size_t N, typename InChar>
inline std::array<unsigned char, N> to_array(std::span<const InChar> sp) {
    std::array<unsigned char, N> result{};
    std::copy_n(
            reinterpret_cast<const unsigned char*>(sp.data()),
            std::min(N, sp.size()),
            result.begin());
    return result;
}

template <typename Container>
inline std::string to_string(const Container& c) {
    return convert<std::string>(c);
}

template <typename Container>
    requires requires(const Container& c) {
        requires sizeof(*c.data()) == 1;
        { c.size() } -> std::convertible_to<std::size_t>;
    }
inline std::string_view to_string_view(const Container& c) {
    return {reinterpret_cast<const char*>(c.data()), static_cast<size_t>(c.size())};
}

// Helper function to go to/from char pointers to unsigned char pointers:
template <oxenc::basic_char Char>
inline const unsigned char* to_unsigned(const Char* x) {
    return reinterpret_cast<const unsigned char*>(x);
}
template <oxenc::basic_char Char>
inline unsigned char* to_unsigned(Char* x) {
    return reinterpret_cast<unsigned char*>(x);
}
inline const unsigned char* to_unsigned(const std::byte* x) {
    return reinterpret_cast<const unsigned char*>(x);
}
inline unsigned char* to_unsigned(std::byte* x) {
    return reinterpret_cast<unsigned char*>(x);
}
// These do nothing, but having them makes template metaprogramming easier:
inline const unsigned char* to_unsigned(const unsigned char* x) {
    return x;
}
inline unsigned char* to_unsigned(unsigned char* x) {
    return x;
}

// The same as std::chrono::system_clock::now(), except that it allows you to get it in a different
// precision.  E.g. sysclock_now<std::chrono::seconds> gives a timepoint with seconds precision (aka
// std::chrono::sys_seconds).
template <typename Precision = std::chrono::system_clock::duration>
inline std::chrono::sys_time<Precision> sysclock_now() {
    return std::chrono::floor<Precision>(std::chrono::system_clock::now());
}
// Shortcut for sysclock_now<std::chrono::seconds>();
inline std::chrono::sys_seconds sysclock_now_s() {
    return sysclock_now<std::chrono::seconds>();
}
using sys_ms = std::chrono::sys_time<std::chrono::milliseconds>;
using sys_seconds = std::chrono::sys_seconds;
// Shortcut for sysclock_now<std::chrono::sys_time<std::chrono::milliseconds>>();
inline sys_ms sysclock_now_ms() {
    return sysclock_now<std::chrono::milliseconds>();
}

// Returns the duration count of the given duration cast into ToDuration.  Example:
//     duration_count<std::chrono::seconds>(30000ms)  // returns 30
// This function requires that the target type is no more precise than d, that is, it will not allow
// you to cast from seconds to milliseconds because such a cast indicates that the sub-second
// precision has already been lost.
template <typename ToDuration, typename Rep, typename Period>
    requires std::is_convertible_v<ToDuration, std::chrono::duration<Rep, Period>>
constexpr int64_t duration_count(const std::chrono::duration<Rep, Period>& d) {
    return std::chrono::duration_cast<ToDuration>(d).count();
}
// Returns the seconds count of the given duration
template <typename Rep, typename Period>
    requires std::is_convertible_v<std::chrono::seconds, std::chrono::duration<Rep, Period>>
constexpr int64_t duration_seconds(const std::chrono::duration<Rep, Period>& d) {
    return duration_count<std::chrono::seconds>(d);
}
// Returns the milliseconds count of the given duration
template <typename Rep, typename Period>
    requires std::is_convertible_v<std::chrono::milliseconds, std::chrono::duration<Rep, Period>>
constexpr int64_t duration_ms(const std::chrono::duration<Rep, Period>& d) {
    return duration_count<std::chrono::milliseconds>(d);
}

// Returns the time-since-epoch count of the given time point, cast into ToDuration.  The given time
// point must be at least as precise as ToDuration, i.e. this will not allow you to cast to a more
// precise time point as that would mean the intended precision has already been lost by an earlier
// cast.
template <class ToDuration, class Clock, class Duration>
    requires std::is_convertible_v<ToDuration, Duration>
constexpr int64_t epoch_count(const std::chrono::time_point<Clock, Duration>& t) {
    return duration_count<ToDuration>(t.time_since_epoch());
}
// Returns the seconds-since-epoch count of the given time point.  The given time point must be at
// least as precise as seconds.
template <class Clock, class Duration>
    requires std::is_convertible_v<std::chrono::seconds, Duration>
constexpr int64_t epoch_seconds(const std::chrono::time_point<Clock, Duration>& t) {
    return duration_seconds(t.time_since_epoch());
}
// Returns the milliseconds-since-epoch count of the given time point.  The given time point must
// have at least milliseconds precision.
template <class Clock, class Duration>
    requires std::is_convertible_v<std::chrono::milliseconds, Duration>
constexpr int64_t epoch_ms(const std::chrono::time_point<Clock, Duration>& t) {
    return duration_ms(t.time_since_epoch());
}

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(std::string_view s1, std::string_view s2) {
    return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    });
}

using uc32 = std::array<unsigned char, 32>;
using uc33 = std::array<unsigned char, 33>;
using uc64 = std::array<unsigned char, 64>;

/// Takes a container of string-like binary values and returns a vector of unsigned char spans
/// viewing those values.  This can be used on a container of any type with a `.data()` and a
/// `.size()` where `.data()` is a one-byte value pointer; std::string, std::string_view,
/// std::vector<const unsigned char>, std::span<const unsigned char>, etc. apply, as does std::array
/// of 1-byte char types.
///
/// This is useful in various libsession functions that require such a vector.  Note that the
/// returned vector's views are valid only as the original container remains alive; this is
/// typically used inline rather than stored, such as:
///
///     session::function_taking_a_view_vector(session::to_view_vector(mydata));
///
/// There are two versions of this: the first takes a generic iterator pair; the second takes a
/// single container.
template <typename It>
std::vector<std::span<const unsigned char>> to_view_vector(It begin, It end) {
    std::vector<std::span<const unsigned char>> vec;
    vec.reserve(std::distance(begin, end));
    for (; begin != end; ++begin) {
        if constexpr (std::is_same_v<std::remove_cv_t<decltype(*begin)>, char*>)  // C strings
            vec.emplace_back(*begin);
        else {
            static_assert(
                    sizeof(*begin->data()) == 1,
                    "to_view_vector can only be used with containers of string-like types of "
                    "1-byte characters");
            vec.emplace_back(reinterpret_cast<const unsigned char*>(begin->data()), begin->size());
        }
    }
    return vec;
}

template <typename Container>
std::vector<std::span<const unsigned char>> to_view_vector(const Container& c) {
    return to_view_vector(c.begin(), c.end());
}

/// Splits a string on some delimiter string and returns a vector of string_view's pointing into the
/// pieces of the original string.  The pieces are valid only as long as the original string remains
/// valid.  Leading and trailing empty substrings are not removed.  If delim is empty you get back a
/// vector of string_views each viewing one character.  If `trim` is true then leading and trailing
/// empty values will be suppressed.
///
///     auto v = split("ab--c----de", "--"); // v is {"ab", "c", "", "de"}
///     auto v = split("abc", ""); // v is {"a", "b", "c"}
///     auto v = split("abc", "c"); // v is {"ab", ""}
///     auto v = split("abc", "c", true); // v is {"ab"}
///     auto v = split("-a--b--", "-"); // v is {"", "a", "", "b", "", ""}
///     auto v = split("-a--b--", "-", true); // v is {"a", "", "b"}
///
std::vector<std::string_view> split(
        std::string_view str, std::string_view delim, bool trim = false);

/// Returns protocol, host, port, path.  Port can be empty; throws on unparseable values.  protocol
/// and host get normalized to lower-case.  Port will be null if not present in the URL, or if set
/// to the default for the protocol.  Path can be empty (a single optional `/` after the domain will
/// be ignored).
std::tuple<std::string, std::string, std::optional<uint16_t>, std::optional<std::string>> parse_url(
        std::string_view url);

/// Truncates a utf-8 encoded string to at most `n` bytes long, but with care as to not truncate in
/// the middle of a unicode codepoint.  If the `n` length would shorten the string such that it
/// terminates in the middle of a utf-8 encoded unicode codepoint then the string is shortened
/// further to not include the sliced unicode codepoint.
///
/// For example, "happy 🎂🎂🎂!!" in utf8 encoding is 20 bytes long:
/// "happy \xf0\x9f\x8e\x82\xf0\x9f\x8e\x82\xf0\x9f\x8e\x82!!", that is:
/// - "happy " (6 bytes)
/// - 🎂 = 0xf0 0x9f 0x8e 0x82 (12 bytes = 3 × 4 bytes each)
/// - "!!" (2 bytes)
/// Truncating this to different lengths results in:
/// - 20, 21, or higher - the 20-byte full string
/// - 19: "happy 🎂🎂🎂!"
/// - 18: "happy 🎂🎂🎂"
/// - 17: "happy 🎂🎂" (14 bytes)
/// - 16, 15, 14: same result as 17
/// - 13, 12, 11, 10: "happy 🎂"
/// - 9, 8, 7, 6: "happy "
/// - 5: "happy"
/// - 4: "happ"
/// - 3: "hap"
/// - 2: "ha"
/// - 1: "a"
/// - 0: ""
///
/// This function is *not* (currently) aware of unicode "characters", but merely codepoints (because
/// grapheme clusters get incredibly complicated).  This is only designed to prevent invalid utf8
/// encodings.  For example, the pair 🇦🇺 (REGIONAL INDICATOR SYMBOL LETTER A, REGIONAL INDICATOR
/// SYMBOL LETTER U) is often rendered as a single Australian flag, but could get chopped here into
/// just 🇦 (REGIONAL INDICATOR SYMBOL LETTER A) rather than removing the getting split in the middle
/// of the pair, which would show up as a decorated A rather than an Australian flag.  Another
/// example, é (LATIN SMALL LETTER E, COMBINING ACUTE ACCENT) could get chopped between the e and
/// the accent modifier, and end up as just "e" in the truncated string.
///
inline std::string utf8_truncate(std::string val, size_t max_bytes) {
    if (val.size() <= max_bytes)
        return val;
    // The *first* char in a utf8 sequence is either:
    // 0b0....... -- single byte encoding, for values up to 0x7f (ascii)
    // 0b11...... -- multi-byte encoding for values >= 0x80; the number of sequential high bit 1's
    // in the first character indicate the sequence length (e.g. 0b1110.... starts a 3-byte
    // sequence).  In our birthday cake encoding, the first byte is \xf0 == 0b11110000, and so it is
    // a 4-byte sequence.
    //
    // That leaves 0x10...... bytes as continuation bytes, each one holding 6 bits of the unicode
    // codepoint, in big endian order, so our birthday cake (in bits): 0b11110000 0b10011111
    // 0b10001110 0b10000010 is the unicode value 0b000 011111 001110 000010 == 0x1f382 == U+1F382:
    // BIRTHDAY CAKE).
    //
    // To prevent slicing, then, we just have to ensure the the first byte after the slice point is
    // *not* a continuation byte (and therefore is either a plain ascii character codepoint, or is
    // the start of a multi-character codepoint).
    while (max_bytes > 0 && (val[max_bytes] & 0b1100'0000) == 0b1000'0000)
        --max_bytes;

    val.resize(max_bytes);
    return val;
}

/// Truncates a UTF-16 encoded string view and returns that same string view truncated to be no more
/// than `max_codepoints` codepoints long.
std::u16string_view utf16_truncate(std::u16string_view in, size_t max_codepoints);

/// Returns the number of unicode codepoints in a utf-16 encoded string.
size_t utf16_count(std::u16string_view utf16_string);

// Helper function to transform a timestamp provided in seconds, milliseconds or microseconds to
// seconds
inline int64_t to_epoch_seconds(int64_t timestamp) {
    return timestamp > 9'000'000'000'000 ? timestamp / 1'000'000
         : timestamp > 9'000'000'000     ? timestamp / 1'000
                                         : timestamp;
}

// Takes a timestamp as unix epoch seconds (not ms, µs) and wraps it in a sys_seconds containing it.
inline std::chrono::sys_seconds as_sys_seconds(int64_t timestamp) {
    return std::chrono::sys_seconds{std::chrono::seconds{timestamp}};
}

// Helper function to transform a timestamp integer that might be seconds, milliseconds or
// microseconds to typesafe system clock seconds unix timestamp.
inline std::chrono::sys_seconds to_sys_seconds(int64_t timestamp) {
    if (timestamp > 9'000'000'000'000)
        timestamp /= 1'000'000;
    else if (timestamp > 9'000'000'000)
        timestamp /= 1'000;
    return as_sys_seconds(timestamp);
}

static_assert(std::is_same_v<
              std::chrono::seconds,
              decltype(std::declval<std::chrono::sys_seconds>().time_since_epoch())>);

/// ZSTD-compresses a value.  `prefix` can be prepended on the returned value, if needed.  Throws on
/// serious error.
std::vector<unsigned char> zstd_compress(
        std::span<const unsigned char> data,
        int level = 1,
        std::span<const unsigned char> prefix = {});

/// ZSTD-decompresses a value.  Returns nullopt if decompression fails.  If max_size is non-zero
/// then this returns nullopt if the decompressed size would exceed that limit.
std::optional<std::vector<unsigned char>> zstd_decompress(
        std::span<const unsigned char> data, size_t max_size = 0);
}  // namespace session

#ifndef _WIN32
// Updates the file descriptor (NOFILE) limit to allow nfiles open fds.  On success, returns the old
// limit as first value, and the new limit as second value.  If the requested nfiles is higher than
// the NOFILE hard limit then this sets the limit to the hard limit instead of the requested value.
// On failure this throws std::system_error containing the error info.
//
// If you pass nfiles=0 then this will not update the FD limit but will simply return the current
// limit (for both return values).
std::pair<rlim_t, rlim_t> set_rlimit_nofile(rlim_t nfiles = 5000);
#endif

template <typename Fn>
Fn make_callback_atomic(Fn cb) {
    auto called = std::make_shared<std::atomic<bool>>(false);

    return [called, cb = std::move(cb)](auto&&... args) {
        if (!called->exchange(true))
            cb(std::forward<decltype(args)>(args)...);
    };
}
