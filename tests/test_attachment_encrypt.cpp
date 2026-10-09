#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <filesystem>
#include <fstream>
#include <session/attachments.hpp>

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
    attachment::Decryptor d{key, [&decrypted](std::span<const std::byte> data) {
                                decrypted.insert(decrypted.end(), data.begin(), data.end());
                            }};

    std::span input{enc};
    while (!input.empty()) {
        auto sz = std::min<size_t>(FEED_SIZE, input.size());
        REQUIRE(d.update(input.first(sz)));
        input = input.subspan(sz);
    }

    REQUIRE(d.finalize());
    CHECK(!!(decrypted == data));
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
            Message("attachment::encrypt requires a 32-byte uploader seed"));

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
