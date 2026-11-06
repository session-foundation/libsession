#include "session/random.hpp"

#include <fmt/ranges.h>
#include <sodium/randombytes.h>

#include <algorithm>
#include <atomic>

#include "session/export.h"
#include "session/random.h"
#include "session/util.hpp"

namespace session::random {

void fill(std::span<std::byte> buf) {
    // An empty span's data() may be null, which libsodium declares it never is.
    if (!buf.empty())
        randombytes_buf(buf.data(), buf.size());
}
void fill(std::span<char> buf) {
    fill(std::span{reinterpret_cast<std::byte*>(buf.data()), buf.size()});
}

void fill_deterministic(std::span<std::byte> buf, std::span<const std::byte, 32> seed) {
    static_assert(seed.extent == randombytes_SEEDBYTES);
    randombytes_buf_deterministic(to_unsigned(buf.data()), buf.size(), to_unsigned(seed.data()));
}

std::vector<std::byte> random(size_t size) {
    std::vector<std::byte> result;
    result.resize(size);
    fill(result);
    return result;
}

static constexpr auto base32_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"sv;
std::string random_base32(size_t size) {
    std::string result;
    result.reserve(size);
    constexpr auto bits_per_char = 5;
    constexpr auto chars_per_draw = 64 / bits_per_char;
    static_assert(1 << bits_per_char == base32_charset.size());
    constexpr uint64_t mask = (1 << bits_per_char) - 1;

    do {
        auto bits = csrng();
        for (int i = 0; result.size() < size && i < chars_per_draw; i++) {
            result.push_back(base32_charset[bits & mask]);
            bits >>= bits_per_char;
        }
    } while (result.size() < size);

    return result;
}

static std::atomic<uint32_t> unique_id_counter{0};

std::string unique_id(std::string_view prefix, size_t random_len) {
    return fmt::format(
            "{}-{}-{}",
            prefix,
            unique_id_counter.fetch_add(1, std::memory_order_relaxed),
            random_base32(random_len));
}

}  // namespace session::random

extern "C" {

LIBSESSION_C_API unsigned char* session_random(size_t size) {
    auto* ret = static_cast<unsigned char*>(malloc(size));
    session::random::fill(std::span{reinterpret_cast<std::byte*>(ret), size});
    return ret;
}

}  // extern "C"
