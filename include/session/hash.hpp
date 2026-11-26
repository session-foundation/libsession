#pragma once

#include <oxenc/common.h>
#include <oxenc/endian.h>

#include <array>
#include <cassert>
#include <initializer_list>
#include <optional>
#include <ranges>
#include <span>
#include <type_traits>
#include <vector>

#include "session/util.hpp"

namespace session::hash {

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function for generating a hash that takes a span
/// to write the hash into.  The size of the hash is determined from the size of the span.
///
/// Inputs:
/// - `hash` -- writable span in which to write the hash.  The size of the span must be between 16
///   and 64.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.  Must be less than 64 bytes long.
///
/// Deprecated: prefer hash::blake2b (unkeyed) or hash::blake2b_key (keyed) instead.
[[deprecated("Use hash::blake2b or hash::blake2b_key instead")]]
void hash(
        std::span<std::byte> hash,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key = std::nullopt);

/// API: hash/hash
///
/// Wrapper around the crypto_generichash_blake2b function that returns a vector of the requested
/// size containing the hash.
///
/// Inputs:
/// - `size` -- length of the hash to be generated.
/// - `msg` -- the message to generate a hash for.
/// - `key` -- an optional key to be used when generating the hash.  Can be omitted or an empty
///   string for an unkeyed hash.
///
/// Outputs:
/// - a `size` byte hash.
///
/// Deprecated: prefer hash::blake2b (unkeyed) or hash::blake2b_key (keyed) instead.
[[deprecated("Use hash::blake2b or hash::blake2b_key instead")]]
std::vector<std::byte> hash(
        const size_t size,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key = std::nullopt);

template <typename T>
concept ByteContainer =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>>;
template <typename T>
concept HashInput =
        ByteContainer<T> || oxenc::endian_swappable_integer<T> || std::same_as<T, std::byte>;

namespace detail {

    template <typename T, size_t N>
    std::integral_constant<size_t, N> extract_extent(const std::array<T, N>&);
    template <typename T, size_t N>
    std::integral_constant<size_t, N> extract_extent(std::span<T, N>);
    template <typename T, size_t N>
    std::integral_constant<size_t, N> extract_extent(const T (&)[N]);
    std::integral_constant<size_t, std::dynamic_extent> extract_extent(...);

    template <typename T>
    constexpr size_t container_extent_v = decltype(extract_extent(std::declval<T&>()))::value;

    template <HashInput U>
    auto make_hashable(const U& val) {
        if constexpr (ByteContainer<U>)
            return std::span{
                    reinterpret_cast<const unsigned char*>(std::ranges::data(val)),
                    std::ranges::size(val)};
        else if constexpr (oxenc::little_endian || sizeof(val) == 1)
            return std::span{reinterpret_cast<const unsigned char*>(&val), sizeof(val)};
        else {
            std::array<unsigned char, sizeof(val)> swapped;
            oxenc::write_host_as_little(val, swapped.data());
            return swapped;
        }
    }

    // Each `parts` list below may refer to temporaries of the caller's full-expression, so it must
    // be consumed before the call returns and never stored.

    // `st` stands in for libsodium's crypto_generichash_blake2b_state so that this header need not
    // include libsodium; src/hash.cpp checks that its size and alignment match.
    class blake2b_hasher_base {
        alignas(64) unsigned char st[384];

      protected:
        // Keys longer than 64 bytes are truncated to 64.
        blake2b_hasher_base(
                size_t outlen,
                std::span<const unsigned char> key,
                std::optional<std::span<const std::byte, 16>> pers);
        ~blake2b_hasher_base();

        blake2b_hasher_base(const blake2b_hasher_base&) = delete;
        blake2b_hasher_base& operator=(const blake2b_hasher_base&) = delete;

        void update(std::initializer_list<std::span<const unsigned char>> parts);
        void finalize(std::span<unsigned char> out);
    };

    // Keccak domain suffix bytes; see the sha3_256 API doc comment for why the domain byte alone
    // distinguishes SHAKE-256 from SHA3-256.
    inline constexpr unsigned char SHAKE256_DOMAIN = 0x1F;
    inline constexpr unsigned char SHA3_256_DOMAIN = 0x06;

    // `st` stands in for libsodium's crypto_xof_shake256_state so that this header need not include
    // libsodium; src/hash.cpp checks that its size and alignment match.
    class keccak_base {
        alignas(16) unsigned char st[256];

      public:
        explicit keccak_base(unsigned char domain);
        ~keccak_base();

        keccak_base(const keccak_base&) = delete;
        keccak_base& operator=(const keccak_base&) = delete;

        void absorb(std::initializer_list<std::span<const unsigned char>> parts);
        void squeeze(std::span<unsigned char> out);
    };

    void sha512(
            std::span<unsigned char, 64> out,
            std::initializer_list<std::span<const unsigned char>> parts);

    void hmac_sha256(
            std::span<unsigned char, 32> out,
            std::span<const unsigned char> key,
            std::initializer_list<std::span<const unsigned char>> parts);

    void argon2(
            std::span<unsigned char> out,
            std::span<const char> password,
            std::span<const std::byte, 16> salt,
            unsigned long long opslimit,
            size_t memlimit,
            int alg);

}  // namespace detail

/// Concept for a fixed-size, writable byte container — the basic requirement for any hash output.
template <typename T>
concept HashOutputContainer =
        std::ranges::contiguous_range<T> && !std::is_const_v<std::ranges::range_value_t<T>> &&
        oxenc::basic_char<std::ranges::range_value_t<T>> &&
        detail::container_extent_v<T> != std::dynamic_extent && detail::container_extent_v<T> >= 1;

namespace detail {

    template <HashOutputContainer Out>
    std::span<unsigned char, container_extent_v<Out>> output_bytes(Out& out) {
        return std::span<unsigned char, container_extent_v<Out>>{
                to_unsigned(std::ranges::data(out)), std::ranges::size(out)};
    }

}  // namespace detail

template <typename T>
concept Blake2BOutputContainer = HashOutputContainer<T> && detail::container_extent_v<T> <= 64;

template <typename T>
concept Blake2BKey =
        std::ranges::contiguous_range<T> && oxenc::basic_char<std::ranges::range_value_t<T>> &&
        (detail::container_extent_v<T> == std::dynamic_extent ||
         detail::container_extent_v<T> <= 64);

/// Helper value to pass a null key to blake2b_key, blake2b_key_pers, or blake2b_hasher (e.g. when
/// only a personalisation string is wanted).
inline constexpr std::span<std::byte, 0> nullkey{};

/// API: hash/blake2b_hasher
///
/// Streaming (piecewise) BLAKE2b hasher with a compile-time fixed output size N (in [1, 64]).
/// Construct with an optional key and/or personalisation string, call update() with data pieces
/// in any order, then call finalize() to produce the result.
///
/// The output size N is a template parameter and is fixed at construction, so init and finalize
/// always agree on the size.
///
/// Like shake256, non-copyable and non-moveable; the internal state is zeroed on destruction.
///
/// Constructors:
///   blake2b_hasher<N>{}              — no key, no pers
///   blake2b_hasher<N>{key, nullopt}  — key only
///   blake2b_hasher<N>{nullkey, pers} — pers only
///   blake2b_hasher<N>{key, pers}     — key + pers
///
/// The two-argument constructor has no default for pers to force explicit intent: if you want
/// only a key, you must write `std::nullopt`; if you want only a pers, you must write `nullkey`.
/// This prevents accidentally passing a `_b2b_pers` value as a key.
///
/// Example:
///
///     hash::blake2b_hasher<32> h{my_key, std::nullopt};
///     h.update(part1, part2);  // update with multiple args at once
///     h.update(part3);         // or call update multiple times
///     auto result = h.finalize();
///
template <size_t N>
    requires(N >= 1 && N <= 64)
struct blake2b_hasher : private detail::blake2b_hasher_base {
    /// No-key, no-pers constructor.
    blake2b_hasher() : blake2b_hasher_base{N, {}, std::nullopt} {}

    /// Key + optional personalisation constructor.  Pass `nullkey` as key for pers-only;
    /// pass `std::nullopt` as pers for key-only.
    ///
    /// Dynamic-extent keys are silently truncated to 64 bytes (the blake2b key size limit);
    /// static-extent keys are guaranteed ≤ 64 at compile time by the Blake2BKey concept.
    template <Blake2BKey Key>
    blake2b_hasher(const Key& key, std::optional<std::span<const std::byte, 16>> pers) :
            blake2b_hasher_base{N, detail::make_hashable(key), pers} {}

    /// Feeds one or more contiguous byte containers or integer values into the hash state, in
    /// argument order.  Integer values are written as raw bytes in little-endian encoding (i.e.
    /// they will be byte-swapped on big-endian platforms if necessary).  May be called multiple
    /// times; each call appends to the state from previous calls.
    template <HashInput... T>
        requires(sizeof...(T) > 0)
    blake2b_hasher& update(const T&... args) {
        blake2b_hasher_base::update({detail::make_hashable(args)...});
        return *this;
    }

    /// Write-to-output finalize: writes the N-byte hash into `out`.
    template <HashOutputContainer Out>
        requires(detail::container_extent_v<Out> == N)
    void finalize(Out& out) {
        blake2b_hasher_base::finalize(detail::output_bytes(out));
    }

    /// Return-value finalize: returns a `std::array<std::byte, N>`.
    std::array<std::byte, N> finalize() {
        std::array<std::byte, N> result;
        finalize(result);
        return result;
    }
};

/// API: hash/blake2b_key
///
/// This version of blake2b() takes a key as the second argument and computes a keyed hash.  The key
/// must be between 0 and 64 characters long.  (A 0-length key is equivalent to no key).
///
/// Two overloads are provided:
/// - write-to-output: `blake2b_key(out, key, args...)` writes the hash into `out`
/// - return-value: `blake2b_key<N>(key, args...)` returns a `std::array<unsigned char, N>`
template <Blake2BOutputContainer Out, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b_key(Out& out, const Key& key, const T&... args) {
    blake2b_hasher<detail::container_extent_v<Out>>{key, std::nullopt}.update(args...).finalize(
            out);
}
template <size_t N, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<std::byte, N> blake2b_key(const Key& key, const T&... args) {
    std::array<std::byte, N> result;
    blake2b_key(result, key, args...);
    return result;
}

/// API: hash/blake2b
///
/// One-shot hasher that takes an output container and any number of contiguous byte containers or
/// integer values, computes the blake2b hash of the concatentation of the containers (in argument
/// order) and then writes the hash into the output container.  Integer values are hashed as their
/// little-endian (fixed size) byte representation.
///
/// This version uses neither key nor personalisation strings; see blake2b_key, blake2b_pers, and
/// blake2b_key_pers if you want one or both of those.
///
/// Output must be a fixed extent span or containers (e.g. std::array), and must satisfy the blake2b
/// requirements (output size in [1,64]).
///
/// It is permitted for overlap between the output and input containers; the output container is not
/// written until all input containers have been consumed.
///
/// Two overloads are provided:
/// - write-to-output: `blake2b(out, args...)` writes the hash into `out`
/// - return-value: `blake2b<N>(args...)` returns a `std::array<unsigned char, N>`
template <Blake2BOutputContainer Out, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b(Out& out, const T&... args) {
    return blake2b_key(out, nullkey, args...);
}
template <size_t N, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<std::byte, N> blake2b(const T&... args) {
    std::array<std::byte, N> result;
    blake2b(result, args...);
    return result;
}

/// API: hash/blake2b_key_pers
///
/// This version of blake2b() takes a both a key and a 16-byte personalisation string as the second
/// and third arguments and computes a keyed hash with a personalisation string.  The
/// personalisation string must be exactly 16 bytes, and is typically constructed with
/// "..."_b2b_pers for compile-time validation.  The key must be between 0 and 64 bytes long.
///
/// Two overloads are provided:
/// - write-to-output: `blake2b_key_pers(out, key, pers, args...)` writes the hash into `out`
/// - return-value: `blake2b_key_pers<N>(key, pers, args...)` returns a `std::array<unsigned char,
/// N>`
template <Blake2BOutputContainer Out, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b_key_pers(
        Out& out, const Key& key, std::span<const std::byte, 16> pers, const T&... args) {
    blake2b_hasher<detail::container_extent_v<Out>>{key, pers}.update(args...).finalize(out);
}
template <size_t N, Blake2BKey Key, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<std::byte, N> blake2b_key_pers(
        const Key& key, std::span<const std::byte, 16> pers, const T&... args) {
    std::array<std::byte, N> result;
    blake2b_key_pers(result, key, pers, args...);
    return result;
}

/// API: hash/blake2b_pers
///
/// This version of blake2b() takes a 16-byte personality string as the second argument and computes
/// a unkeyed hash with a personalisation string.  The personalization string must be exact 16
/// bytes, and is typically constructed with "..."_b2b_pers for compile-time validation.
///
/// Two overloads are provided:
/// - write-to-output: `blake2b_pers(out, pers, args...)` writes the hash into `out`
/// - return-value: `blake2b_pers<N>(pers, args...)` returns a `std::array<unsigned char, N>`
template <Blake2BOutputContainer Out, HashInput... T>
    requires(sizeof...(T) > 0)
void blake2b_pers(Out& out, std::span<const std::byte, 16> pers, const T&... args) {
    return blake2b_key_pers(out, nullkey, pers, args...);
}
template <size_t N, HashInput... T>
    requires(sizeof...(T) > 0 && N >= 1 && N <= 64)
std::array<std::byte, N> blake2b_pers(std::span<const std::byte, 16> pers, const T&... args) {
    std::array<std::byte, N> result;
    blake2b_pers(result, pers, args...);
    return result;
}

/// API: hash/shake256
///
/// SHAKE256 XOF hasher/squeezer.  Construct with any number of contiguous byte containers or
/// integer values to absorb their concatenation, then call operator() with one or more fixed-size
/// output containers to squeeze output.  Multiple operator() calls squeeze sequentially.  Integer
/// values are absorbed as their little-endian (fixed-size) byte representation.
///
/// Unlike blake2b, SHAKE256 has no key or personalisation mechanism; callers achieve domain
/// separation by simply prepending a domain string as the first argument.
///
/// The internal keccak state is zeroed on destruction.
///
/// Example:
///
///     // Squeeze two outputs in one call:
///     hash::shake256("SessionMyKey"_bytes, seed)(out_a, out_b);
///
///     // Or squeeze incrementally:
///     hash::shake256 sq{"SessionMyKey"_bytes, seed};
///     sq(out_a);
///     sq(out_b);
///
struct [[nodiscard]] shake256 : private detail::keccak_base {
    template <HashInput... T>
        requires(sizeof...(T) > 0)
    explicit shake256(const T&... args) : keccak_base{detail::SHAKE256_DOMAIN} {
        absorb({detail::make_hashable(args)...});
    }

    template <HashOutputContainer... Outs>
        requires(sizeof...(Outs) > 0)
    shake256& operator()(Outs&&... outs) {
        (keccak_base::squeeze(detail::output_bytes(outs)), ...);
        return *this;
    }

    /// Squeezes N bytes from the state and returns them as a `std::array<std::byte, N>`.
    template <size_t N>
        requires(N >= 1)
    std::array<std::byte, N> squeeze() {
        std::array<std::byte, N> result;
        (*this)(result);
        return result;
    }
};

/// API: hash/sha3_256
///
/// One-shot SHA3-256 (NIST FIPS 202) hasher.  Takes a fixed-size 32-byte output container and any
/// number of contiguous byte containers or integer values, computes the SHA3-256 hash of their
/// concatenation (in argument order), and writes the result into the output container.  Integer
/// values are hashed as their little-endian (fixed-size) byte representation.
///
/// Implementation note: SHA3-256 and SHAKE-256 share identical Keccak-1600 sponge parameters
/// (state=1600 bits, rate=136 bytes, capacity=512 bits) and differ *only* in the domain suffix
/// byte absorbed into the state during padding before the final squeeze:
///
///   - SHAKE-256: 0x1F  (FIPS 202 §6.2 XOF suffix '11111')
///   - SHA3-256:  0x06  (FIPS 202 §6.1 hash suffix '01', plus the leading '1' of the Keccak
///                       multi-rate padding '10*1', making the combined byte '0000 0110')
///
/// Because the sponge parameters are identical, initialising libsodium's SHAKE-256 state with
/// crypto_xof_shake256_init_with_domain(&st, 0x06), then absorbing input and squeezing 32 bytes, is
/// exactly SHA3-256.  This is the intended use of init_with_domain, not a workaround.
///
/// The temporary keccak state is zeroed before this function returns.
///
/// Two overloads are provided:
/// - write-to-output: `sha3_256(out, args...)` writes the hash into `out`
/// - return-value: `sha3_256<32>(args...)` returns a `std::array<std::byte, 32>`
template <HashOutputContainer Out, HashInput... T>
    requires(detail::container_extent_v<Out> == 32 && sizeof...(T) > 0)
void sha3_256(Out& out, const T&... args) {
    detail::keccak_base keccak{detail::SHA3_256_DOMAIN};
    keccak.absorb({detail::make_hashable(args)...});
    keccak.squeeze(detail::output_bytes(out));
}
template <size_t N, HashInput... T>
    requires(N == 32 && sizeof...(T) > 0)
std::array<std::byte, 32> sha3_256(const T&... args) {
    std::array<std::byte, 32> result;
    sha3_256(result, args...);
    return result;
}

// Helper callable usable with unordered_map and similar to hash an array of chars by simply copying
// the first sizeof(size_t) bytes, suitable for use with pre-hashed values.
struct identity_hasher {
    template <oxenc::basic_char Char, size_t N>
        requires(N >= sizeof(size_t))
    constexpr size_t operator()(const std::array<Char, N>& v) const noexcept {
        size_t out;
        std::copy(v.begin(), v.begin() + sizeof(out), reinterpret_cast<Char*>(&out));
        return out;
    }
};

// ─── SHA-512 ─────────────────────────────────────────────────────────────────

/// One-shot SHA-512 hasher.  Takes a fixed-size 64-byte output container and any number of
/// contiguous byte containers or integer values, computes the SHA-512 hash of their concatenation
/// (in argument order), and writes the result into the output container.
template <HashOutputContainer Out, HashInput... T>
    requires(detail::container_extent_v<Out> == 64 && sizeof...(T) > 0)
void sha512(Out& out, const T&... args) {
    detail::sha512(detail::output_bytes(out), {detail::make_hashable(args)...});
}

// ─── HMAC-SHA-256 ────────────────────────────────────────────────────────────

/// One-shot HMAC-SHA-256.  Takes a fixed-size 32-byte output container, a key (any byte
/// container), and any number of contiguous byte containers or integer values, computes the
/// HMAC-SHA-256 of their concatenation and writes the result into the output container.
template <HashOutputContainer Out, ByteContainer Key, HashInput... T>
    requires(detail::container_extent_v<Out> == 32 && sizeof...(T) > 0)
void hmac_sha256(Out& out, const Key& key, const T&... args) {
    detail::hmac_sha256(
            detail::output_bytes(out),
            detail::make_hashable(key),
            {detail::make_hashable(args)...});
}

// ─── Argon2id (password hashing / KDF) ───────────────────────────────────────

inline constexpr size_t ARGON2_SALTBYTES = 16;
inline constexpr unsigned long long ARGON2_OPSLIMIT_MODERATE = 3;
inline constexpr size_t ARGON2_MEMLIMIT_MODERATE = 268435456;
inline constexpr int ARGON2ID13 = 2;

/// Derives a key from a password using Argon2id (libsodium crypto_pwhash).
/// Throws std::runtime_error if the derivation fails (e.g. out of memory).
///
/// Inputs:
/// - `out`      -- writable byte container to receive the derived key (between 16 and 4294967295
///                 bytes).
/// - `password` -- the password/input data.
/// - `salt`     -- the 16-byte Argon2 salt (`ARGON2_SALTBYTES`).
/// - `opslimit` -- CPU cost parameter (e.g. `ARGON2_OPSLIMIT_MODERATE`).
/// - `memlimit` -- memory cost parameter (e.g. `ARGON2_MEMLIMIT_MODERATE`).
/// - `alg`      -- algorithm selector (e.g. `ARGON2ID13`).
template <HashOutputContainer Out>
    requires(detail::container_extent_v<Out> >= 16)
void argon2(
        Out& out,
        std::span<const char> password,
        std::span<const std::byte, ARGON2_SALTBYTES> salt,
        unsigned long long opslimit,
        size_t memlimit,
        int alg) {
    detail::argon2(detail::output_bytes(out), password, salt, opslimit, memlimit, alg);
}

}  // namespace session::hash

namespace session { inline namespace literals { inline namespace hash_literals {

    /// User-defined literal for a 16-byte personalization value for use with BLAKE2b.
    /// Enforces the 16-byte length at compile time via the requires clause.  Returns a
    /// fixed-extent span so it passes directly to blake2b_pers / blake2b_key_pers.
    ///
    /// Like the standard library's sub-literal namespaces (e.g. `std::literals::chrono_literals`),
    /// it can be brought in with any of:
    ///
    ///     using namespace session::literals;       // every session literal
    ///     using namespace session::hash_literals;  // only the hash literals
    ///     using namespace session::hash;           // along with the rest of session::hash
    ///
    /// `using namespace session;` also brings it in, and code inside namespace `session` needs no
    /// using-directive at all.  Example:
    ///
    ///     constexpr auto PERS_XYZ = "XYZ-XYZ-XYZ-WXYZ"_b2b_pers;
    ///
    template <BytesLiteral Lit>
        requires(Lit.size == 16)
    consteval auto operator""_b2b_pers() {
        return operator""_bytes < Lit>();
    }

}}}  // namespace session::literals::hash_literals

namespace session::hash {
using namespace literals::hash_literals;
}
