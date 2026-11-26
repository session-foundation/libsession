#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>

#include "session/hash.h"
#include "session/hash.hpp"
#include "session/util.hpp"
#include "utils.hpp"

using namespace session::literals;

TEST_CASE("Hash generation", "[hash][hash]") {
    // Intentionally exercising the deprecated hash::hash() to verify it still works.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    auto hash1 = session::hash::hash(32, session::to_span("TestMessage"), std::nullopt);
    auto hash2 = session::hash::hash(32, session::to_span("TestMessage"), std::nullopt);
    auto hash3 =
            session::hash::hash(32, session::to_span("TestMessage"), session::to_span("TestKey"));
    auto hash4 =
            session::hash::hash(32, session::to_span("TestMessage"), session::to_span("TestKey"));
    auto hash5 = session::hash::hash(64, session::to_span("TestMessage"), std::nullopt);
    auto hash6 =
            session::hash::hash(64, session::to_span("TestMessage"), session::to_span("TestKey"));
    CHECK_THROWS(session::hash::hash(10, session::to_span("TestMessage"), std::nullopt));
    CHECK_THROWS(session::hash::hash(100, session::to_span("TestMessage"), std::nullopt));
    CHECK_THROWS(session::hash::hash(
            32,
            session::to_span("TestMessage"),
            session::to_span("KeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLongKeyThatIsTooLongKeyTh"
                             "atIsTooLon"
                             "g")));
#pragma GCC diagnostic pop

    CHECK(hash1.size() == 32);
    CHECK(hash2.size() == 32);
    CHECK(hash3.size() == 32);
    CHECK(hash4.size() == 32);
    CHECK(hash5.size() == 64);
    CHECK(hash6.size() == 64);
    CHECK(hash1 == hash2);
    CHECK(hash1 != hash3);
    CHECK(hash3 == hash4);
    CHECK(hash1 != hash5);
    CHECK(hash3 != hash6);
    CHECK(to_hex(hash1) == "2a48a12262e4548afb97fe2b04a912a02297d451169ee7ef2d01a28ea20286ab");
    CHECK(to_hex(hash2) == "2a48a12262e4548afb97fe2b04a912a02297d451169ee7ef2d01a28ea20286ab");
    CHECK(to_hex(hash3) == "3d643e479b626bb2907476e32ccf7bdbd1ac3efa0da6e2c335255c48dcc216b6");
    CHECK(to_hex(hash4) == "3d643e479b626bb2907476e32ccf7bdbd1ac3efa0da6e2c335255c48dcc216b6");

    auto expected_hash5 =
            "9d9085ac026fe3542abbeb2ea2ec05f5c37aecd7695f6cc41e9ccf39014196a39c02db69c44"
            "16d5c45acc2e9469b7f274992b2858f3bb2746becb48c8b56ce4b";
    auto expected_hash6 =
            "6a2faad89cf9010a4270cba07cc96cfb36688106e080b15fef66bb03c68e877874c9059edf5"
            "3d03c1330b2655efdad6e4aa259118b6ea88698ea038efb9d52ce";
    CHECK(to_hex(hash5) == expected_hash5);
    CHECK(to_hex(hash6) == expected_hash6);
}

TEST_CASE("blake2b_hasher", "[hash][blake2b]") {
    using session::b32;
    using session::hash::blake2b_hasher;
    using session::hash::nullkey;

    // The deprecated hash::hash calls libsodium directly (no blake2b_hasher involvement) and serves
    // as the independent reference for the no-pers cases below.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // ── No-key, no-pers ──────────────────────────────────────────────────────────────────────
    // KAT value cross-checks against deprecated hash::hash (independent libsodium path).

    {
        auto out = blake2b_hasher<32>{}.update("TestMessage"_bytes).finalize();
        auto ref = session::hash::hash(32, session::to_span("TestMessage"), std::nullopt);
        CHECK(std::ranges::equal(out, ref));
        CHECK(to_hex(out) == "2a48a12262e4548afb97fe2b04a912a02297d451169ee7ef2d01a28ea20286ab");
    }

    {
        auto out = blake2b_hasher<64>{}.update("TestMessage"_bytes).finalize();
        auto ref = session::hash::hash(64, session::to_span("TestMessage"), std::nullopt);
        CHECK(std::ranges::equal(out, ref));
        CHECK(to_hex(out) ==
              "9d9085ac026fe3542abbeb2ea2ec05f5c37aecd7695f6cc41e9ccf39014196a3"
              "9c02db69c4416d5c45acc2e9469b7f274992b2858f3bb2746becb48c8b56ce4b");
    }

    // ── Keyed, no-pers ───────────────────────────────────────────────────────────────────────

    {
        auto out = blake2b_hasher<32>{"TestKey"_bytes, std::nullopt}
                           .update("TestMessage"_bytes)
                           .finalize();
        auto ref = session::hash::hash(
                32, session::to_span("TestMessage"), session::to_span("TestKey"));
        CHECK(std::ranges::equal(out, ref));
        CHECK(to_hex(out) == "3d643e479b626bb2907476e32ccf7bdbd1ac3efa0da6e2c335255c48dcc216b6");
    }

    {
        auto out = blake2b_hasher<64>{"TestKey"_bytes, std::nullopt}
                           .update("TestMessage"_bytes)
                           .finalize();
        auto ref = session::hash::hash(
                64, session::to_span("TestMessage"), session::to_span("TestKey"));
        CHECK(std::ranges::equal(out, ref));
        CHECK(to_hex(out) ==
              "6a2faad89cf9010a4270cba07cc96cfb36688106e080b15fef66bb03c68e8778"
              "74c9059edf53d03c1330b2655efdad6e4aa259118b6ea88698ea038efb9d52ce");
    }

#pragma GCC diagnostic pop

    // ── Multi-update consistency ──────────────────────────────────────────────────────────────
    // Splitting the input across calls must yield the same hash.

    {
        auto single = blake2b_hasher<32>{}.update("TestMessage"_bytes).finalize();
        auto multi = blake2b_hasher<32>{}
                             .update("Test"_bytes)  // split across two calls
                             .update("Message"_bytes)
                             .finalize();
        CHECK(single == multi);

        b32 out_write;
        blake2b_hasher<32>{}.update("TestMes"_bytes, "sage"_bytes).finalize(out_write);
        CHECK(single == out_write);
    }

    // ── Return-value vs write-to-output finalize ──────────────────────────────────────────────

    {
        b32 out_write;
        blake2b_hasher<32>{}.update("TestMessage"_bytes).finalize(out_write);
        auto out_rv = blake2b_hasher<32>{}.update("TestMessage"_bytes).finalize();
        CHECK(out_write == out_rv);
    }

    // ── Personalisation string changes output ─────────────────────────────────────────────────

    constexpr auto pers = "TestPers1234567!"_b2b_pers;

    b32 no_pers_out, pers_out;
    blake2b_hasher<32>{}.update("TestMessage"_bytes).finalize(no_pers_out);
    blake2b_hasher<32>{nullkey, pers}.update("TestMessage"_bytes).finalize(pers_out);
    CHECK(no_pers_out != pers_out);

    // Pers is deterministic: same config and input → same output.
    b32 pers_out2;
    blake2b_hasher<32>{nullkey, pers}.update("TestMessage"_bytes).finalize(pers_out2);
    CHECK(pers_out == pers_out2);

    // Pers + multi-update consistency.
    b32 pers_multi;
    blake2b_hasher<32>{nullkey, pers}
            .update("Test"_bytes)
            .update("Message"_bytes)
            .finalize(pers_multi);
    CHECK(pers_out == pers_multi);

    // Different pers → different output.
    constexpr auto pers2 = "OtherPers123456!"_b2b_pers;
    b32 pers2_out;
    blake2b_hasher<32>{nullkey, pers2}.update("TestMessage"_bytes).finalize(pers2_out);
    CHECK(pers_out != pers2_out);

    // ── Key + pers ────────────────────────────────────────────────────────────────────────────

    b32 key_pers_out;
    blake2b_hasher<32>{"TestKey"_bytes, pers}.update("TestMessage"_bytes).finalize(key_pers_out);
    // Distinct from keyed-only, pers-only, and no-key/no-pers outputs.
    CHECK(key_pers_out != pers_out);
    CHECK(key_pers_out != no_pers_out);
    // Consistent across repeated construction.
    b32 key_pers_out2;
    blake2b_hasher<32>{"TestKey"_bytes, pers}.update("TestMessage"_bytes).finalize(key_pers_out2);
    CHECK(key_pers_out == key_pers_out2);
}

TEST_CASE("SHA3-256 and SHAKE-256 known-answer tests", "[hash][sha3_256][shake256]") {
    // This test case serves two purposes:
    // 1. Verify SHA3-256 against NIST FIPS 202 known-answer test vectors.
    // 2. Verify SHAKE-256 against NIST FIPS 202 known-answer test vectors.
    // 3. Confirm that SHA3-256 and SHAKE-256 produce different output on identical input,
    //    verifying that the domain suffix byte (0x06 vs 0x1F) is actually applied.
    //
    // SHA3-256 KATs:
    // https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/sha3/sha-3bittestvectors.zip
    // SHAKE-256 KATs: NIST FIPS 202, Appendix A / CAVS test data

    using session::b32;
    using session::hash::sha3_256;
    using session::hash::shake256;

    b32 sha3_out, shake_out;

    // --- SHA3-256 NIST vectors ---

    // Empty input
    sha3_256(sha3_out, ""_bytes);
    CHECK(oxenc::to_hex(sha3_out) ==
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    // "abc" (24 bits)
    sha3_256(sha3_out, "abc"_bytes);
    CHECK(oxenc::to_hex(sha3_out) ==
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    // 448-bit message
    sha3_256(sha3_out, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"_bytes);
    CHECK(oxenc::to_hex(sha3_out) ==
          "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");

    // 896-bit message
    sha3_256(
            sha3_out,
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklm"
            "nopqklmnopqrlmnopqrsmnopqrstnopqrstu"_bytes);
    CHECK(oxenc::to_hex(sha3_out) ==
          "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");

    // --- SHAKE-256 NIST vectors (32-byte output) ---

    // Empty input; first 32 bytes from FIPS 202 Appendix B.2 sample output
    shake256(""_bytes)(shake_out);
    CHECK(oxenc::to_hex(shake_out) ==
          "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

    // "abc" (24 bits)
    shake256("abc"_bytes)(shake_out);
    CHECK(oxenc::to_hex(shake_out) ==
          "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");

    // --- Cross-check: same input must produce different output ---
    sha3_256(sha3_out, "abc"_bytes);
    shake256("abc"_bytes)(shake_out);
    CHECK(sha3_out != shake_out);
}

TEST_CASE("blake2b_pers integer args are little-endian", "[hash][blake2b][endian]") {
    using session::hash::blake2b_pers;

    // make_hashable() must serialize integer arguments as fixed-width little-endian, independent of
    // host endianness — the byte encoding underpinning every Session Pro signed digest. Pin the
    // contract by requiring an integer to hash identically to its explicit little-endian bytes. On
    // a little-endian host this guards the direct-reinterpret path; on a big-endian host (run via
    // utils/test-bigendian.sh) it is the only thing exercising make_hashable's byte-swap branch.
    constexpr auto pers = "EndianTestPers!!"_b2b_pers;

    {
        uint16_t v = 0x0102;
        std::array<std::byte, 2> le{std::byte{0x02}, std::byte{0x01}};
        CHECK(blake2b_pers<32>(pers, v) == blake2b_pers<32>(pers, le));
    }
    {
        uint32_t v = 0x01020304;
        std::array<std::byte, 4> le{
                std::byte{0x04}, std::byte{0x03}, std::byte{0x02}, std::byte{0x01}};
        CHECK(blake2b_pers<32>(pers, v) == blake2b_pers<32>(pers, le));
    }
    {
        uint64_t v = 0x0102030405060708ULL;
        std::array<std::byte, 8> le{
                std::byte{0x08},
                std::byte{0x07},
                std::byte{0x06},
                std::byte{0x05},
                std::byte{0x04},
                std::byte{0x03},
                std::byte{0x02},
                std::byte{0x01}};
        CHECK(blake2b_pers<32>(pers, v) == blake2b_pers<32>(pers, le));
    }
}

TEST_CASE("blake2b keys longer than 64 bytes are truncated", "[hash][blake2b]") {
    using session::hash::blake2b_hasher;

    std::vector<std::byte> key(80);
    for (size_t i = 0; i < key.size(); i++)
        key[i] = static_cast<std::byte>(i);

    auto full = blake2b_hasher<32>{key, std::nullopt}.update("TestMessage"_bytes).finalize();
    auto first64 = blake2b_hasher<32>{std::span{key}.first(64), std::nullopt}
                           .update("TestMessage"_bytes)
                           .finalize();
    CHECK(full == first64);
}

TEST_CASE("SHA-512 and HMAC-SHA-256 known-answer tests", "[hash][sha512][hmac_sha256]") {
    using session::hash::hmac_sha256;
    using session::hash::sha512;

    // The integer arguments are the little-endian encodings of the text they stand in for, so the
    // known answers also pin make_hashable's byte order when mixed with containers in one call.

    // FIPS 180-2 "abc"
    constexpr auto abc_sha512 =
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    std::array<std::byte, 64> h512;
    sha512(h512, "abc"_bytes);
    CHECK(oxenc::to_hex(h512) == abc_sha512);
    sha512(h512, std::byte{'a'}, uint16_t{0x6362});
    CHECK(oxenc::to_hex(h512) == abc_sha512);
    sha512(h512, uint16_t{0x6261}, std::string_view{"c"});
    CHECK(oxenc::to_hex(h512) == abc_sha512);

    // RFC 4231 test case 2
    constexpr auto jefe_hmac = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    session::b32 mac;
    hmac_sha256(mac, "Jefe"_bytes, "what do ya want for nothing?"_bytes);
    CHECK(oxenc::to_hex(mac) == jefe_hmac);
    hmac_sha256(
            mac,
            std::string_view{"Jefe"},
            uint32_t{0x74616877},
            " do ya want "_bytes,
            std::string{"for nothing?"});
    CHECK(oxenc::to_hex(mac) == jefe_hmac);
}
