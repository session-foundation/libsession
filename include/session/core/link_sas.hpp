#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace session::core {

/// A short authentication string: 21 indices, each 0-63, into the SAS emoji table (see
/// `sas_emoji`).  The first 7 are the standard display, in a row; all 21 are for the extended
/// view, as 3 rows of 7.  The indices themselves are never shown to a user: they are what an
/// application looks the emoji and their names up by, in whatever language it shows them.
using Sas = std::array<uint8_t, 21>;

/// One of the 64 SAS emoji, from the Matrix client-server API specification v1.17, section
/// 10.12.2.2.6, in Matrix's order: the emoji, and the English description Matrix gives it
/// (`data-definitions/sas-emoji.json`), which a client shows beside it -- or a translation of
/// it, which an application looks up by the same index.
struct SasEmoji {
    std::string_view emoji;
    std::string_view description;
};

/// The emoji at `index` (0-63) of the SAS table.  Throws std::out_of_range for anything else.
const SasEmoji& sas_emoji(uint8_t index);

/// Argon2id parameters for the SAS seed derivation; see "Handshake short authentication string".
inline constexpr unsigned long long SAS_ARGON2_OPSLIMIT = 2;
inline constexpr size_t SAS_ARGON2_MEMLIMIT = 64 * 1024 * 1024;

/// Computes the Argon2id seed underlying the SAS for a device link request.  The derivation is:
///   1. salt = BLAKE2b-16(M, pers="SessionLinkEmoji")
///   2. seed = Argon2id(M, salt, size=16, ops=SAS_ARGON2_OPSLIMIT, mem=SAS_ARGON2_MEMLIMIT)
///
/// The seed can be stored to avoid re-running the expensive Argon2id computation; pass it to
/// sas_from_seed() to recover the SAS at any time.
std::array<std::byte, 16> derive_sas_seed(std::span<const std::byte> plaintext);

/// Extracts the 21 SAS indices from a pre-computed seed (as returned by derive_sas_seed).  This is
/// a cheap bit-extraction operation with no cryptographic cost.
Sas sas_from_seed(std::span<const std::byte, 16> seed);

/// Convenience wrapper: derives the seed and immediately returns the SAS.
Sas link_request_sas(std::span<const std::byte> plaintext);

}  // namespace session::core
