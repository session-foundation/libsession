#pragma once

#include <cassert>
#include <charconv>
#include <concepts>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace session::pro {

/// Builds the byte string that is Ed25519-signed for a Pro proof (§2) or a signed request (§3),
/// following the signed-message construction in pro-wire-protocol.md §1.1. Pass the 16-byte domain
/// prefix first, then the fields in order; each field is encoded by its type:
///
/// - **byte-spannable** (public key, revocation tag — fixed-width raw values): appended verbatim
///   and self-delimiting;
/// - **integer**: canonical decimal ASCII (`std::to_chars`, base 10, locale-independent — never a
///   locale-aware formatter);
/// - **string_view** (e.g. the opaque `before` pagination cursor of get_payment_details): its bytes
///   verbatim.
///
/// A single NUL byte is inserted between two *adjacent* variable-length fields (integer/string);
/// raw fields need no separator, and the domain prefix (also raw) never precedes one. The message
/// is signed directly — there is no pre-hash (Ed25519 hashes internally).
template <typename... Fields>
std::vector<unsigned char> signed_message(std::string_view domain, const Fields&... fields) {
    std::vector<unsigned char> buf(domain.begin(), domain.end());
    bool prev_var = false;  // the previously-appended field was variable-length (int/string)

    auto append = [&](const auto& field) {
        using T = std::remove_cvref_t<decltype(field)>;
        if constexpr (std::is_integral_v<T>) {
            if (prev_var)
                buf.push_back('\0');
            char tmp[24];  // enough for -9223372036854775808 (20 chars)
            auto [ptr, ec] = std::to_chars(tmp, tmp + sizeof(tmp), field);
            assert(ec == std::errc{});  // tmp is large enough for any integer, so this cannot fail
            buf.insert(buf.end(), tmp, ptr);
            prev_var = true;
        } else if constexpr (std::convertible_to<const T&, std::string_view>) {
            if (prev_var)
                buf.push_back('\0');
            std::string_view s = field;
            buf.insert(buf.end(), s.begin(), s.end());
            prev_var = true;
        } else {
            static_assert(
                    std::convertible_to<const T&, std::span<const unsigned char>>,
                    "signed_message() fields must be an integer, a string_view, or a "
                    "byte-spannable raw value (e.g. a public key or tag)");
            std::span<const unsigned char> b = field;
            buf.insert(buf.end(), b.begin(), b.end());
            prev_var = false;
        }
    };
    (append(fields), ...);
    return buf;
}

}  // namespace session::pro
