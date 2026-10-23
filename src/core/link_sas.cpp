#include <oxenc/endian.h>
#include <sodium/crypto_pwhash.h>

#include <session/core/link_sas.hpp>
#include <session/hash.hpp>
#include <stdexcept>

using namespace session::literals;
using namespace std::literals;

namespace session::core {

namespace {

    constexpr std::array<SasEmoji, 64> SAS_EMOJI = {{
            // clang-format off
            {"🐶"sv, "Dog"sv},        {"🐱"sv, "Cat"sv},        {"🦁"sv, "Lion"sv},
            {"🐎"sv, "Horse"sv},      {"🦄"sv, "Unicorn"sv},    {"🐷"sv, "Pig"sv},
            {"🐘"sv, "Elephant"sv},   {"🐰"sv, "Rabbit"sv},     {"🐼"sv, "Panda"sv},
            {"🐓"sv, "Rooster"sv},    {"🐧"sv, "Penguin"sv},    {"🐢"sv, "Turtle"sv},
            {"🐟"sv, "Fish"sv},       {"🐙"sv, "Octopus"sv},    {"🦋"sv, "Butterfly"sv},
            {"🌷"sv, "Flower"sv},     {"🌳"sv, "Tree"sv},       {"🌵"sv, "Cactus"sv},
            {"🍄"sv, "Mushroom"sv},   {"🌏"sv, "Globe"sv},      {"🌙"sv, "Moon"sv},
            {"☁️"sv, "Cloud"sv},      {"🔥"sv, "Fire"sv},       {"🍌"sv, "Banana"sv},
            {"🍎"sv, "Apple"sv},      {"🍓"sv, "Strawberry"sv}, {"🌽"sv, "Corn"sv},
            {"🍕"sv, "Pizza"sv},      {"🎂"sv, "Cake"sv},       {"❤️"sv, "Heart"sv},
            {"😀"sv, "Smiley"sv},     {"🤖"sv, "Robot"sv},      {"🎩"sv, "Hat"sv},
            {"👓"sv, "Glasses"sv},    {"🔧"sv, "Spanner"sv},    {"🎅"sv, "Santa"sv},
            {"👍"sv, "Thumbs Up"sv},  {"☂️"sv, "Umbrella"sv},   {"⌛"sv, "Hourglass"sv},
            {"⏰"sv, "Clock"sv},      {"🎁"sv, "Gift"sv},       {"💡"sv, "Light Bulb"sv},
            {"📕"sv, "Book"sv},       {"✏️"sv, "Pencil"sv},     {"📎"sv, "Paperclip"sv},
            {"✂️"sv, "Scissors"sv},   {"🔒"sv, "Lock"sv},       {"🔑"sv, "Key"sv},
            {"🔨"sv, "Hammer"sv},     {"☎️"sv, "Telephone"sv},  {"🏁"sv, "Flag"sv},
            {"🚂"sv, "Train"sv},      {"🚲"sv, "Bicycle"sv},    {"✈️"sv, "Aeroplane"sv},
            {"🚀"sv, "Rocket"sv},     {"🏆"sv, "Trophy"sv},     {"⚽"sv, "Ball"sv},
            {"🎸"sv, "Guitar"sv},     {"🎺"sv, "Trumpet"sv},    {"🔔"sv, "Bell"sv},
            {"⚓"sv, "Anchor"sv},     {"🎧"sv, "Headphones"sv}, {"📁"sv, "Folder"sv},
            {"📌"sv, "Pin"sv},
            // clang-format on
    }};

}  // namespace

const SasEmoji& sas_emoji(uint8_t index) {
    return SAS_EMOJI.at(index);
}

std::array<std::byte, 16> derive_sas_seed(std::span<const std::byte> plaintext) {
    auto salt = hash::blake2b_pers<16>("SessionLinkEmoji"_b2b_pers, plaintext);

    std::array<std::byte, 16> seed;
    if (0 != crypto_pwhash(
                     reinterpret_cast<unsigned char*>(seed.data()),
                     seed.size(),
                     reinterpret_cast<const char*>(plaintext.data()),
                     plaintext.size(),
                     reinterpret_cast<const unsigned char*>(salt.data()),
                     SAS_ARGON2_OPSLIMIT,
                     SAS_ARGON2_MEMLIMIT,
                     crypto_pwhash_ALG_ARGON2ID13))
        throw std::runtime_error{"derive_sas_seed: Argon2id key derivation failed"};

    return seed;
}

Sas sas_from_seed(std::span<const std::byte, 16> seed) {
    // Interpret the 16-byte seed as a 128-bit little-endian integer split into two 64-bit words.
    uint64_t lo = oxenc::load_little_to_host<uint64_t>(seed.data());
    uint64_t hi = oxenc::load_little_to_host<uint64_t>(seed.data() + 8);

    Sas result;
    for (int k = 0; k < 21; k++) {
        int bit = k * 6;
        if (bit + 6 <= 64)
            result[k] = (lo >> bit) & 0x3F;
        else if (bit >= 64)
            result[k] = (hi >> (bit - 64)) & 0x3F;
        else
            // Single crossing point: k=10, bit=60.
            // Low 4 bits come from lo (bits 60-63), high 2 bits come from hi (bits 64-65).
            result[k] = ((lo >> 60) | (hi << 4)) & 0x3F;
    }
    return result;
}

Sas link_request_sas(std::span<const std::byte> plaintext) {
    return sas_from_seed(derive_sas_seed(plaintext));
}

}  // namespace session::core
