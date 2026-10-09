#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "types.h"

namespace session {

template <typename T, typename... U>
static constexpr bool is_one_of = (std::is_same_v<T, U> || ...);

using array_uc32 = std::array<std::uint8_t, 32>;
using array_uc33 = std::array<std::uint8_t, 33>;
using array_uc64 = std::array<std::uint8_t, 64>;

enum class SessionIDPrefix {
    standard = 0,
    group = 0x3,
    community_blinded_legacy = 0x5,
    community_blinded = 0x15,
    version_blinded = 0x25,
    unblinded = 0x7,
};

namespace config {
    using seqno_t = std::int64_t;
}

/// Create a span of bytes that owns the `size` bytes of memory requested. If allocation fails, this
/// function throws a runtime exception. The `data` pointer is span must be freed once the span
/// is no longer needed.
span_u8 span_u8_alloc_or_throw(size_t size);

/// Create a span of bytes that copies the payload at `data` for `size` bytes. If allocation fails
/// this function throws a runtime exception. The `data` pointer is span must be freed once the span
/// is no longer needed.
span_u8 span_u8_copy_or_throw(const void* data, size_t size);

}  // namespace session
