#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <filesystem>
#include <fstream>
#include <session/attachments.hpp>
#include <session/random.hpp>

#include "utils.hpp"

using namespace session::config;

namespace attachment = session::attachment;

static std::vector<std::byte> make_data(size_t len) {
    std::vector<std::byte> v;
    v.reserve(len);
    for (int i = 0; i < len; i++)
        v.push_back(static_cast<std::byte>(i * 7 % 256));
    return v;
}

using Catch::Matchers::Message;

TEST_CASE("Attachment encryption/decryption", "[attachments]") {

    auto DATA_SIZE = GENERATE(
            0,
            1,
            2,
            10,
            100,
            1000,
            2000,
            4000,
            4053,
            4054,
            8149,
            8150,
            33333,
            261982,
            261983,
            523990,
            523991,
            6543210,
            10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE < 8150      ? 8192
                       : DATA_SIZE < 10000     ? 12288
                       : DATA_SIZE == 33333    ? 36864
                       : DATA_SIZE < 261983    ? 262144
                       : DATA_SIZE < 262000    ? 270336
                       : DATA_SIZE < 523991    ? 524288
                       : DATA_SIZE < 524000    ? 540672
                       : DATA_SIZE == 6543210  ? 6553600
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    auto [enc2, key2] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    CHECK(oxenc::to_hex(key) == oxenc::to_hex(key2));
    CHECK(enc.size() == expected_size);
    CHECK(!!(enc == enc2));  // Prevent catch2 from trying to expand this on failure

    auto decr = attachment::decrypt(enc, key);
    CHECK(decr == data);
}

TEST_CASE("Attachment encryption/decryption -- large files", "[attachments][large]") {

    auto DATA_SIZE = GENERATE(0, 60'000, 10'000'000, 25'000'000);

    auto expected_size = DATA_SIZE == 0        ? 4096
                       : DATA_SIZE == 60000    ? 61440
                       : DATA_SIZE == 10000000 ? 10223616
                       : DATA_SIZE == 25000000 ? 25165824
                                               : -1;

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    std::vector<std::byte> data;
    data.reserve(DATA_SIZE);
    for (int i = 0; i < DATA_SIZE; i++)
        data.push_back(static_cast<std::byte>(i * 7 % 256));

    std::vector<std::byte> enc;
    std::array<std::byte, attachment::ENCRYPT_KEY_SIZE> key;
    if (DATA_SIZE > 10'000'000) {
        CHECK_THROWS_MATCHES(
                std::tie(enc, key) =
                        attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT),
                std::invalid_argument,
                Message("data to encrypt is too large"));
    }
    std::tie(enc, key) = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT, true);

    CHECK(enc.size() == expected_size);

    auto decr = attachment::decrypt(enc, key);
    CHECK(!!(decr == data));
}

const auto bad_data_message =
        Message("Attachment decryption failed: invalid key or corrupted data");

TEST_CASE("Attachment encryption/decryption -- key separation", "[attachments][key-sep]") {

    auto DATA_SIZE = GENERATE(0, 20, 100, 1000, 33333);

    auto seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    auto seed2 = GENERATE(
            "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b,
            "0123456789abcdef0123456789abcdef1123456789abcdef0123456789abcdef"_hex_b,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde7"_hex_b);

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    auto [enc2, key2] = attachment::encrypt(seed2, data, attachment::Domain::ATTACHMENT);

    CHECK(oxenc::to_hex(key) != oxenc::to_hex(key2));
    CHECK(!(enc == enc2));

    CHECK_THROWS_MATCHES(attachment::decrypt(enc, key2), std::runtime_error, bad_data_message);
    CHECK_THROWS_MATCHES(attachment::decrypt(enc2, key), std::runtime_error, bad_data_message);
}

TEST_CASE("Attachment encryption/decryption -- key separation", "[attachments][domain-sep]") {

    auto DATA_SIZE = GENERATE(0, 20, 100, 1000, 33333);

    auto seed = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    auto [enc2, key2] = attachment::encrypt(seed, data, attachment::Domain::PROFILE_PIC);

    CHECK(oxenc::to_hex(key) != oxenc::to_hex(key2));
    CHECK(!(enc == enc2));

    CHECK_THROWS_MATCHES(attachment::decrypt(enc, key2), std::runtime_error, bad_data_message);
    CHECK_THROWS_MATCHES(attachment::decrypt(enc2, key), std::runtime_error, bad_data_message);
}

TEST_CASE("Attachment encryption/decryption -- content separation", "[attachments][content-sep]") {

    auto seed = "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(50000);
    auto data2 = data;
    data2[43210] = std::byte{0x42};

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    auto [enc2, key2] = attachment::encrypt(seed, data2, attachment::Domain::ATTACHMENT);

    CHECK(oxenc::to_hex(key) != oxenc::to_hex(key2));
    CHECK(enc.size() == enc2.size());
    CHECK(!(enc == enc2));

    CHECK_THROWS_MATCHES(attachment::decrypt(enc, key2), std::runtime_error, bad_data_message);
    CHECK_THROWS_MATCHES(attachment::decrypt(enc2, key), std::runtime_error, bad_data_message);
}

TEST_CASE("Attachment Decryptor", "[attachments][decryptor]") {

    auto DATA_SIZE = GENERATE(
            0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 8149, 8150, 33333, 6543210, 10218286);

    auto FEED_SIZE = GENERATE(1, 2, 41, 4096, 10000000000);

    auto seed = "4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    std::vector<std::byte> decrypted;
    std::vector<std::optional<size_t>> padding_seen;
    attachment::Decryptor* self = nullptr;
    attachment::Decryptor d{key, [&](std::span<const std::byte> data) {
                                padding_seen.push_back(self->padding());
                                decrypted.insert(decrypted.end(), data.begin(), data.end());
                            }};
    self = &d;
    CHECK_FALSE(d.padding());

    std::span input{enc};
    while (!input.empty()) {
        auto sz = std::min<size_t>(FEED_SIZE, input.size());
        REQUIRE(d.update(input.first(sz)));
        input = input.subspan(sz);
    }

    REQUIRE(d.finalize());
    CHECK(!!(decrypted == data));

    // The padding is known by the time the first byte of data comes out -- which is what lets a
    // copy with the same padding be started before the data's length is known -- and it is the
    // padding the encryption chose.
    REQUIRE(d.padding());
    for (const auto& p : padding_seen)
        CHECK(p == d.padding());
    CHECK(*d.padding() == attachment::encrypted_padding(DATA_SIZE));
}

TEST_CASE("Attachment PushEncryptor", "[attachments][encryptor]") {
    auto DATA_SIZE = GENERATE(0, 1, 100, 32767, 32768, 32769, 65536, 200'000, 6543210);
    auto FEED_SIZE = GENERATE(1, 41, 32768, 10000000);

    const auto data = make_data(DATA_SIZE);
    cleared_b32 key;
    session::random::fill(key);

    // Re-encrypting with the padding a download carried reproduces it exactly: the same layout as
    // the Encryptor's, down to the byte count.  The padding is what an honest sender's Encryptor
    // chose, since that is what a cached copy of their file starts from.
    auto padding = attachment::encrypted_padding(DATA_SIZE);
    std::vector<std::byte> enc;
    attachment::PushEncryptor e{key, padding, [&](std::span<const std::byte> out) {
                                    enc.insert(enc.end(), out.begin(), out.end());
                                }};
    for (std::span input{data}; !input.empty();) {
        auto sz = std::min<size_t>(FEED_SIZE, input.size());
        e.update(input.first(sz));
        input = input.subspan(sz);
    }
    e.finalize();
    CHECK(enc.size() == attachment::encrypted_size(DATA_SIZE));

    // ...and reads back, through both the whole-buffer and the streaming decryption, with the
    // padding it was given.
    CHECK(!!(attachment::decrypt(enc, key) == data));

    std::vector<std::byte> decrypted;
    attachment::Decryptor d{key, [&](std::span<const std::byte> out) {
                                decrypted.insert(decrypted.end(), out.begin(), out.end());
                            }};
    REQUIRE(d.update(enc));
    REQUIRE(d.finalize());
    CHECK(!!(decrypted == data));
    CHECK(d.padding() == padding);

    CHECK_THROWS_AS(e.update(data), std::logic_error);
    CHECK_THROWS_AS(e.finalize(), std::logic_error);
}

TEST_CASE(
        "Attachment PushEncryptor keeps whatever padding it is given", "[attachments][encryptor]") {
    // Not only the padding the Encryptor would choose: a sender's file may carry any amount,
    // including more than a chunk of it, or none but the marker.
    auto PADDING = GENERATE(1, 2, 32768, 32769, 100'000);
    const auto data = make_data(5000);
    cleared_b32 key;
    session::random::fill(key);

    std::vector<std::byte> enc;
    attachment::PushEncryptor e{key, static_cast<size_t>(PADDING), [&](auto out) {
                                    enc.insert(enc.end(), out.begin(), out.end());
                                }};
    e.update(data);
    e.finalize();

    std::vector<std::byte> decrypted;
    attachment::Decryptor d{key, [&](std::span<const std::byte> out) {
                                decrypted.insert(decrypted.end(), out.begin(), out.end());
                            }};
    REQUIRE(d.update(enc));
    REQUIRE(d.finalize());
    CHECK(!!(decrypted == data));
    CHECK(d.padding() == static_cast<size_t>(PADDING));

    // The marker is part of the padding, so there is no such thing as none.
    CHECK_THROWS_AS(attachment::PushEncryptor(key, 0, [](auto) {}), std::invalid_argument);
}

struct temp_data_file {
    inline static int i = 1;
    std::filesystem::path path =
            std::filesystem::temp_directory_path() /
            std::filesystem::path{"libsession-util-attachment-test-{}"_format(i++)};

    ~temp_data_file() {
        if (std::filesystem::exists(path))
            std::filesystem::remove(path);
    }

    // Constructs a temp filename without actually creating the file
    temp_data_file() = default;

    // Constructs a plaintext file with deterministic output based on its size:
    explicit temp_data_file(int len) {
        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(path, std::ios::binary | std::ios::trunc);
        for (int i = 0; i < len; i++) {
            std::byte v{static_cast<std::byte>(i * 7 % 256)};
            out.write(reinterpret_cast<const char*>(&v), 1);
        }
    }
};

TEST_CASE(
        "Attachment encryption: plaintext file to encrypted buffer",
        "[attachments][files][encrypt]") {

    auto DATA_SIZE = GENERATE(0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 261983, 10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE == 4054     ? 8192
                       : DATA_SIZE == 261983   ? 270336
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    temp_data_file f{DATA_SIZE};

    auto [enc, key] = attachment::encrypt(seed, f.path, attachment::Domain::ATTACHMENT);
    CHECK(enc.size() == expected_size);
    auto decr = attachment::decrypt(enc, key);
    CHECK(!!(decr == make_data(DATA_SIZE)));
}

TEST_CASE("Attachment file encryption validates its inputs", "[attachments][files][encrypt]") {
    auto seed = "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    temp_data_file f{0};

    CHECK_THROWS_MATCHES(
            attachment::encrypt(
                    std::span{seed}.first<31>(), f.path, attachment::Domain::ATTACHMENT),
            std::invalid_argument,
            Message("attachment::Encryptor requires a 32-byte uploader seed"));

    std::filesystem::resize_file(f.path, attachment::MAX_REGULAR_SIZE + 1);
    CHECK_THROWS_MATCHES(
            attachment::encrypt(seed, f.path, attachment::Domain::ATTACHMENT),
            std::invalid_argument,
            Message("data to encrypt is too large"));

    auto [enc, key] = attachment::encrypt(seed, f.path, attachment::Domain::ATTACHMENT, true);
    CHECK(attachment::decrypt(enc, key).size() == attachment::MAX_REGULAR_SIZE + 1);
}

static std::vector<std::byte> slurp_file(const std::filesystem::path& filename) {
    std::ifstream in;
    in.exceptions(std::ios::failbit | std::ios::badbit);
    in.open(filename, std::ios::binary | std::ios::ate);
    auto endpos = in.tellg();
    in.seekg(0, std::ios::beg);
    auto size = endpos - in.tellg();

    std::vector<std::byte> contents;
    contents.resize(size);
    in.read(reinterpret_cast<char*>(contents.data()), contents.size());

    return contents;
}

static void write_file(const std::filesystem::path& filename, std::span<const std::byte> contents) {
    std::ofstream out;
    out.exceptions(std::ios::failbit | std::ios::badbit);
    out.open(filename, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
}

static void corrupt_last_byte(std::vector<std::byte>& data) {
    REQUIRE(!data.empty());
    data.back() ^= std::byte{0x01};
}

static void corrupt_first_full_chunk(std::vector<std::byte>& data) {
    constexpr size_t first_chunk_offset = 1 + attachment::ENCRYPT_HEADER;
    REQUIRE(data.size() > first_chunk_offset + attachment::ENCRYPTED_CHUNK_TOTAL);
    data[first_chunk_offset] ^= std::byte{0x01};
}

TEST_CASE(
        "Attachment encryption: plaintext buffer to encrypted file",
        "[attachments][files][encrypt]") {

    auto DATA_SIZE = GENERATE(0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 261983, 10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE == 4054     ? 8192
                       : DATA_SIZE == 261983   ? 270336
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    auto data = make_data(DATA_SIZE);
    temp_data_file f;

    auto key = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT, f.path);
    auto enc = slurp_file(f.path);
    CHECK(enc.size() == expected_size);
    auto decr = attachment::decrypt(enc, key);
    CHECK(!!(decr == data));
}

TEST_CASE(
        "Attachment decryption: encrypted buffer to plaintext file",
        "[attachments][files][decrypt]") {

    auto DATA_SIZE = GENERATE(0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 261983, 10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE == 4054     ? 8192
                       : DATA_SIZE == 261983   ? 270336
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);
    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);

    temp_data_file out{};

    attachment::decrypt(enc, key, out.path);

    auto contents = slurp_file(out.path);
    CHECK(contents.size() == data.size());
    CHECK(!!(contents == data));
}

TEST_CASE(
        "Attachment decryption: encrypted file to plaintext buffer",
        "[attachments][files][decrypt]") {

    auto DATA_SIZE = GENERATE(0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 261983, 10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE == 4054     ? 8192
                       : DATA_SIZE == 261983   ? 270336
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    temp_data_file out;
    auto key = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT, out.path);

    auto decrypted = attachment::decrypt(out.path, key);

    CHECK(decrypted.size() == data.size());
    CHECK(!!(decrypted == data));
}

TEST_CASE(
        "Attachment decryption: encrypted file to plaintext file",
        "[attachments][files][decrypt]") {

    auto DATA_SIZE = GENERATE(0, 1, 2, 10, 100, 1000, 2000, 4000, 4053, 4054, 261983, 10218286);

    auto expected_size = DATA_SIZE < 4054      ? 4096
                       : DATA_SIZE == 4054     ? 8192
                       : DATA_SIZE == 261983   ? 270336
                       : DATA_SIZE == 10218286 ? 10223616
                                               : -1;

    auto seed = "9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;

    const auto data = make_data(DATA_SIZE);

    temp_data_file out_enc, out_dec;
    auto key = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT, out_enc.path);

    attachment::decrypt(out_enc.path, key, out_dec.path);

    auto contents = slurp_file(out_dec.path);
    CHECK(contents.size() == data.size());
    CHECK(!!(contents == data));
}

TEST_CASE(
        "Attachment streaming decryption rejects corrupted data", "[attachments][files][decrypt]") {

    auto seed = "a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    auto data = make_data(1000);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    corrupt_last_byte(enc);

    SECTION("encrypted buffer to plaintext file") {
        temp_data_file out;

        CHECK_THROWS_MATCHES(
                attachment::decrypt(enc, key, out.path), std::runtime_error, bad_data_message);
        CHECK_FALSE(std::filesystem::exists(out.path));
    }

    SECTION("encrypted file to plaintext buffer") {
        temp_data_file encrypted_file;
        write_file(encrypted_file.path, enc);

        CHECK_THROWS_MATCHES(
                attachment::decrypt(encrypted_file.path, key),
                std::runtime_error,
                bad_data_message);
    }

    SECTION("encrypted file to plaintext file") {
        temp_data_file encrypted_file;
        temp_data_file out;
        write_file(encrypted_file.path, enc);

        CHECK_THROWS_MATCHES(
                attachment::decrypt(encrypted_file.path, key, out.path),
                std::runtime_error,
                bad_data_message);
        CHECK_FALSE(std::filesystem::exists(out.path));
    }
}

TEST_CASE(
        "Attachment streaming decryption rejects corrupted full chunks",
        "[attachments][files][decrypt]") {

    auto seed = "b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    auto data = make_data(attachment::ENCRYPT_CHUNK_SIZE * 2);

    auto [enc, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    corrupt_first_full_chunk(enc);

    SECTION("encrypted buffer to plaintext file") {
        temp_data_file out;

        CHECK_THROWS_MATCHES(
                attachment::decrypt(enc, key, out.path), std::runtime_error, bad_data_message);
        CHECK_FALSE(std::filesystem::exists(out.path));
    }

    SECTION("encrypted file to plaintext buffer") {
        temp_data_file encrypted_file;
        write_file(encrypted_file.path, enc);

        CHECK_THROWS_MATCHES(
                attachment::decrypt(encrypted_file.path, key),
                std::runtime_error,
                bad_data_message);
    }

    SECTION("encrypted file to plaintext file") {
        temp_data_file encrypted_file;
        temp_data_file out;
        write_file(encrypted_file.path, enc);

        CHECK_THROWS_MATCHES(
                attachment::decrypt(encrypted_file.path, key, out.path),
                std::runtime_error,
                bad_data_message);
        CHECK_FALSE(std::filesystem::exists(out.path));
    }
}

TEST_CASE("Streaming Encryptor", "[attachments][encryptor]") {

    auto DATA_SIZE = GENERATE(0, 1, 100, 1000, 4053, 8150, 32768, 65536, 100000);

    auto seed = "9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
    const auto data = make_data(DATA_SIZE);

    SECTION("pull-based encryption with manual source") {
        attachment::Encryptor enc{seed, attachment::Domain::ATTACHMENT};

        // Phase 1: feed data in chunks to derive key
        for (size_t pos = 0; pos < data.size();) {
            size_t chunk = std::min<size_t>(1000, data.size() - pos);
            enc.update_key(std::span{data}.subspan(pos, chunk));
            pos += chunk;
        }
        if (data.empty())
            enc.update_key({});

        // Phase 2: start encryption with a pull source
        size_t src_pos = 0;
        auto key = enc.start_encryption([&](std::span<std::byte> buf) -> size_t {
            size_t avail = std::min(buf.size(), data.size() - src_pos);
            std::memcpy(buf.data(), data.data() + src_pos, avail);
            src_pos += avail;
            return avail;
        });

        // Collect all encrypted output
        std::vector<std::byte> encrypted;
        while (true) {
            auto chunk = enc.next();
            if (chunk.empty())
                break;
            encrypted.insert(encrypted.end(), chunk.begin(), chunk.end());
        }

        CHECK(encrypted.size() == attachment::encrypted_size(DATA_SIZE));

        // Decrypt with the streaming Decryptor and verify round-trip
        std::vector<std::byte> decrypted;
        attachment::Decryptor dec{key, [&](std::span<const std::byte> d) {
                                      decrypted.insert(decrypted.end(), d.begin(), d.end());
                                  }};
        REQUIRE(dec.update(encrypted));
        REQUIRE(dec.finalize());
        REQUIRE(decrypted.size() == data.size());
        CHECK(!!(decrypted == data));
    }

    SECTION("from_file factory") {
        if (DATA_SIZE == 0)
            return;  // Can't write an empty file for this test

        // Write test data to a temp file
        temp_data_file tmp;
        {
            std::ofstream f{tmp.path, std::ios::binary};
            f.write(reinterpret_cast<const char*>(data.data()), data.size());
        }

        auto [enc, key] = attachment::Encryptor::from_file(
                seed, attachment::Domain::ATTACHMENT, tmp.path, true);

        std::vector<std::byte> encrypted;
        while (true) {
            auto chunk = enc.next();
            if (chunk.empty())
                break;
            encrypted.insert(encrypted.end(), chunk.begin(), chunk.end());
        }

        CHECK(encrypted.size() == attachment::encrypted_size(DATA_SIZE));

        // Decrypt and verify
        auto decrypted = attachment::decrypt(encrypted, key);
        REQUIRE(decrypted.size() == data.size());
        CHECK(!!(decrypted == data));
    }
}

// -- Legacy (AES-CBC + HMAC) attachments ---------------------------------------------------------
//
// The scheme every Session client still *sends*, inherited from libsignal: 32-byte AES key followed
// by a 32-byte HMAC key, and a file laid out as IV || AES-256-CBC(PKCS#7) || HMAC-SHA256(IV||ct),
// with the AttachmentPointer's `digest` being SHA-256 over all three.
//
// The vectors below were produced by an independent implementation (python-cryptography) written
// from session-android's AttachmentCipherInputStream, so this is a known-answer test rather than a
// round trip against ourselves -- which would prove nothing, since libsession deliberately has no
// legacy *encryptor*.

using namespace oxenc::literals;

namespace {

constexpr auto LEGACY_KEY =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"_hex_b;

// "the quick brown fox jumps over the lazy dog, repeatedly and at length." -- 70 bytes, with no
// Session-level zero padding, so the pointer's size is the plaintext length.
constexpr auto LEGACY_BLOB =
        "6465666768696a6b6c6d6e6f7071727339c6cadce50e036612224f681bbbe3f3"
        "1acc5779dfe5367b18c6272231f4eb139a9b56725e81236c469883304bc53999"
        "311ae9c035bf6ed5d2fbd6fb24777de2d1368b650f24d5c454208af7610238a9"
        "ff4892a7b4b5e54a9b99e78d73d65f335fc5c5559dd3d4c894401d0c7f7ce95b"_hex_b;
constexpr auto LEGACY_DIGEST =
        "68af9ac56f2c7d90a984f9edccdd538765b0e3ba2c1958ce7c0071212c0beccb"_hex_b;
constexpr auto LEGACY_PLAINTEXT =
        "the quick brown fox jumps over the lazy dog, repeatedly and at length."sv;

// 20 real bytes zero-padded out to 200, which is what the pointer's size is actually for.
constexpr auto PADDED_BLOB =
        "6465666768696a6b6c6d6e6f70717273e85b4762c96dc9f8ec01d8cce057ce81"
        "f52ba3a6d5b7b61214a1000d827532b1c36cc1beb5454eb154e159508cd627f5"
        "349d55e9a583df1ad46401d07805608c89ba1ca437e93067b91a18efc3af88e7"
        "8247d47fb3562ee73b5e9de5c538caebeeb6e36787f98745414735371311d90a"
        "6a169349eb0ecc93b5b45076f95daef493d7663ef1e538e7b28c60aff8e5528c"
        "c221d7c1e1ce092184b140a68a9adfe1738ae283e50701d83e370d75f57e6f3f"
        "7fcb2a0f410ac34187e414c3bb6d5cf38399b89cafa402e061c675ab409b9eb0"
        "849ead65dbccc86863b3b1817d37cd6eb8b50dc259e90fbb4971620dd09eabb9"_hex_b;
constexpr auto PADDED_DIGEST =
        "da2680f942213633344c39c0690c652beed7e1c50f6ceef45e113dc0f007fd33"_hex_b;

auto legacy_key() {
    return std::span<const std::byte, attachment::LEGACY_KEY_SIZE>{LEGACY_KEY};
}
auto legacy_digest() {
    return std::span<const std::byte, attachment::LEGACY_DIGEST_SIZE>{LEGACY_DIGEST};
}
auto padded_digest() {
    return std::span<const std::byte, attachment::LEGACY_DIGEST_SIZE>{PADDED_DIGEST};
}

}  // namespace

TEST_CASE("legacy attachment decryption", "[attachments][legacy]") {
    auto out = attachment::legacy_decrypt(
            LEGACY_BLOB, legacy_key(), legacy_digest(), LEGACY_PLAINTEXT.size());
    CHECK(session::to_string_view(out) == LEGACY_PLAINTEXT);

    // A sender too old to set the field leaves the zero padding in place rather than having it
    // guessed at, so what comes back is the whole PKCS#7-stripped plaintext.
    auto untrimmed = attachment::legacy_decrypt(PADDED_BLOB, legacy_key(), padded_digest(), 0);
    CHECK(untrimmed.size() == 200);

    // ...and with the field set, only the real bytes.
    auto trimmed = attachment::legacy_decrypt(PADDED_BLOB, legacy_key(), padded_digest(), 20);
    REQUIRE(trimmed.size() == 20);
    CHECK(session::to_string_view(trimmed) == "twenty bytes exactly"sv);
}

TEST_CASE("legacy attachment decryption rejects bad input", "[attachments][legacy]") {
    auto tampered = [](std::span<const std::byte> blob, size_t at) {
        std::vector<std::byte> v{blob.begin(), blob.end()};
        v[at] ^= std::byte{0x01};
        return v;
    };

    // A flipped bit anywhere in the file fails the HMAC, whether it lands in the IV, the ciphertext
    // or the MAC itself.  Nothing is decrypted before that check.
    for (size_t at : {size_t{0}, size_t{20}, LEGACY_BLOB.size() - 1})
        CHECK_THROWS(attachment::legacy_decrypt(
                tampered(LEGACY_BLOB, at), legacy_key(), legacy_digest(), LEGACY_PLAINTEXT.size()));

    // A correct file with a wrong digest is *accepted*, deliberately: we do not verify it.  The
    // HMAC checked above covers the same bytes under a key only the sender has, so anything a bad
    // digest could catch has already failed -- see the reasoning where that check is commented out.
    //
    // Asserted rather than left implicit because it is a decision, and the natural instinct on
    // finding an unverified authenticator is to start verifying it.
    auto wrong_digest = tampered(LEGACY_DIGEST, 5);
    CHECK(attachment::legacy_decrypt(
                  LEGACY_BLOB,
                  legacy_key(),
                  std::span<const std::byte, attachment::LEGACY_DIGEST_SIZE>{wrong_digest},
                  LEGACY_PLAINTEXT.size()) == to_vector<std::byte>(LEGACY_PLAINTEXT));

    // The one a hostile sender controls directly: a size larger than what was decrypted. Refused
    // rather than clamped, since the pointer is then lying about its own file.
    CHECK_THROWS(attachment::legacy_decrypt(
            LEGACY_BLOB, legacy_key(), legacy_digest(), LEGACY_PLAINTEXT.size() + 1));
    CHECK_THROWS(attachment::legacy_decrypt(
            LEGACY_BLOB, legacy_key(), legacy_digest(), std::numeric_limits<size_t>::max()));

    // Too short to hold an IV, a block and a MAC.
    CHECK_THROWS(attachment::legacy_decrypt(
            LEGACY_BLOB.subspan(0, 40), legacy_key(), legacy_digest(), 1));

    // Not a whole number of cipher blocks, so it cannot be what a CBC encryptor produced.
    CHECK_THROWS(attachment::legacy_decrypt(
            LEGACY_BLOB.subspan(0, LEGACY_BLOB.size() - 1), legacy_key(), legacy_digest(), 1));
}

TEST_CASE("Attachment encryption -- a key of our own", "[attachments][fixed-key]") {
    // Encrypting to our own disk rather than to a file server: the key is ours, kept once and
    // reused, so nothing about the content decides it.
    cleared_b32 cache_key;
    session::random::fill(cache_key);

    std::vector<std::byte> plaintext(70'000);
    session::random::fill(plaintext);

    auto encrypt_with = [&](std::span<const std::byte> data) {
        attachment::Encryptor enc{cache_key};
        size_t pos = 0;
        enc.start_encryption(
                [&](std::span<std::byte> buf) -> size_t {
                    auto n = std::min(buf.size(), data.size() - pos);
                    std::memcpy(buf.data(), data.data() + pos, n);
                    pos += n;
                    return n;
                },
                false,
                data.size());

        std::vector<std::byte> out;
        for (auto chunk = enc.next(); !chunk.empty(); chunk = enc.next())
            out.insert(out.end(), chunk.begin(), chunk.end());
        return out;
    };

    auto encrypted = encrypt_with(plaintext);

    // Reads back with the ordinary decrypt: same format, so there is one decryptor, not two.
    CHECK(attachment::decrypt(encrypted, cache_key) == plaintext);

    // Not deterministic, which is the point of the random nonce: the seed-based encryptor
    // deliberately repeats itself so a file server can deduplicate, and repeating a keystream
    // under one key across every cached file is the failure that would cause here.
    auto again = encrypt_with(plaintext);
    CHECK(again != encrypted);
    CHECK(attachment::decrypt(again, cache_key) == plaintext);

    // Another key does not open it.
    cleared_b32 other;
    session::random::fill(other);
    CHECK_THROWS(attachment::decrypt(encrypted, other));

    // Padded exactly as the seed-based path is: a local disk ends up in backups and disk images,
    // and an exact size identifies a file as well there as on a file server.
    CHECK(encrypted.size() == attachment::encrypted_size(plaintext.size()));

    // Phase 1 has no meaning here, and asking for it is a mistake rather than a no-op.
    attachment::Encryptor enc{cache_key};
    CHECK_THROWS_AS(enc.update_key(plaintext), std::logic_error);
    // ...and without phase 1 nothing knows how much is coming, so the size is required.
    CHECK_THROWS_AS(
            enc.start_encryption([](std::span<std::byte>) -> size_t { return 0; }),
            std::invalid_argument);
}

TEST_CASE("Display picture decryption -- the legacy GCM scheme", "[attachments][legacy-pic]") {
    // Session has three at-rest formats and nothing in the bytes says which is which.  This is the
    // one display pictures used before the stream scheme: AES-256-GCM, 32-byte key, nonce and tag
    // carried in the data -- unrelated to the legacy *attachment* scheme, which is CBC with a
    // bolted-on HMAC, a 64-byte key and a digest carried in the protobuf.
    //
    // The vector is from python-cryptography rather than from our own encryptor, so this cannot
    // pass by agreeing with itself.
    constexpr auto key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex_b;
    constexpr auto blob =
            "000102030405060708090a0b2622b272b695ae7af461e7e2d29d0d1fe6faa7559c173a1b5d0389fc903a"
            "65df450ae8c0b3070d5d413b790c"_hex_b;
    constexpr auto expected = "a display picture, allegedly"sv;

    auto plain = attachment::legacy_display_pic_decrypt(blob, key);
    CHECK(std::string_view{reinterpret_cast<const char*>(plain.data()), plain.size()} == expected);

    // A flipped bit anywhere fails on the tag rather than yielding rubbish.
    std::vector<std::byte> tampered{blob.begin(), blob.end()};
    tampered[20] ^= std::byte{0x01};
    CHECK_THROWS(attachment::legacy_display_pic_decrypt(tampered, key));

    // As does the wrong key.
    constexpr auto wrong = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"_hex_b;
    CHECK_THROWS(attachment::legacy_display_pic_decrypt(blob, wrong));

    // Too short to hold a nonce and a tag is refused rather than read past.
    CHECK_THROWS(attachment::legacy_display_pic_decrypt(blob.subspan(0, 27), key));
}

TEST_CASE(
        "legacy attachment decryption holds the sender to the size they claimed",
        "[attachments][legacy][size]") {
    // Over-reporting has always failed: the claim exceeds what came out.
    CHECK_THROWS(attachment::legacy_decrypt(
            LEGACY_BLOB, legacy_key(), legacy_digest(), LEGACY_PLAINTEXT.size() + 1));

    // Under-reporting is *not* caught, and cannot be: the bytes past the claim would have to be
    // recognisable as padding, and session-android's padding is whatever its read buffer happened
    // to contain (PaddingInputStream reports bulk padding without writing it).  So a sender who
    // under-reports gets a silently truncated file, and the legacy format offers no way to tell.
    CHECK(attachment::legacy_decrypt(
                  LEGACY_BLOB, legacy_key(), legacy_digest(), LEGACY_PLAINTEXT.size() - 1)
                  .size() == LEGACY_PLAINTEXT.size() - 1);

    // The honest claim still works, and the padding that legitimately follows it is dropped.
    CHECK(attachment::legacy_decrypt(
                  LEGACY_BLOB, legacy_key(), legacy_digest(), LEGACY_PLAINTEXT.size()) ==
          to_vector<std::byte>(LEGACY_PLAINTEXT));

    // Zero still means "the sender never said", which only clients predating the field do, and
    // leaves the padding in place rather than guessing.
    CHECK(attachment::legacy_decrypt(LEGACY_BLOB, legacy_key(), legacy_digest(), 0).size() >=
          LEGACY_PLAINTEXT.size());
}
