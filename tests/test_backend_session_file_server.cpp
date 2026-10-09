#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/util.hpp>

#include "utils.hpp"

using namespace session::network;

TEST_CASE("Download url parsing", "[backend][session_file_server]") {

    auto parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Strips a trailing forward slash from the file_id
    parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123/"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Identifies that the url wants stream-based decryption
    parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123/#d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK(parsed_download_url->wants_stream_decryption);

    // Extracts the custom pubkey
    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Ignores the pubkey if it matches the default one
    parsed_download_url = file_server::parse_download_url(fmt::format(
            "https://example.com/file/abc123#p={}"sv, file_server::DEFAULT_CONFIG.pubkey_hex));
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->custom_pubkey_hex.has_value());
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Handles both fragments
    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000&d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK(parsed_download_url->wants_stream_decryption);

    // Handles both fragments in the opposite order
    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#d&p=0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->scheme == "https"sv);
    CHECK(parsed_download_url->host == "example.com"sv);
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK(parsed_download_url->wants_stream_decryption);

    // A valueless `d=` is NOT the stream-encryption fragment.  Session Desktop builds its fragment
    // with URLSearchParams, which serialises a valueless key with the `=`, so its stream-encrypted
    // uploads are read as legacy by every client that parses the url through here.
    parsed_download_url = file_server::parse_download_url("https://example.com/file/abc123#d="sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->file_id == "abc123"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    parsed_download_url = file_server::parse_download_url(
            "https://example.com/file/abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000&d="sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->custom_pubkey_hex ==
          "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Doesn't have an issue with a legacy url
    parsed_download_url = file_server::parse_download_url(
            "http://filev2.getsession.org/files/2478430809375318"sv);
    CHECK(parsed_download_url.has_value());

    // Doesn't have an issue with a url that isn't in the right format
    parsed_download_url = file_server::parse_download_url("https://example.com/test/test2"sv);
    CHECK_FALSE(parsed_download_url.has_value());
}

TEST_CASE("Download url generation", "[backend][session_file_server]") {
    auto url = file_server::generate_download_url(
            "abc123"sv,
            {"http",
             "example.com",
             123,
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             12345,
             true});
    CHECK(url ==
          "http://example.com:123/file/"
          "abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000&d");

    // Omits the stream encryption fragment when disabled
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http",
             "example.com",
             123,
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             12345,
             false});
    CHECK(url ==
          "http://example.com:123/file/"
          "abc123#p=0123456789abcdef0123456789abcdef00000000000000000000000000000000");

    // Omits the pubkey when it matches the default pubkey
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http", "example.com", 123, file_server::DEFAULT_CONFIG.pubkey_hex, 12345, true});
    CHECK(url == "http://example.com:123/file/abc123#d");

    // Omits all fragments when stream encryption is disabled and the default pubkey is used
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http", "example.com", 123, file_server::DEFAULT_CONFIG.pubkey_hex, 12345, false});
    CHECK(url == "http://example.com:123/file/abc123");

    // Works with other values
    url = file_server::generate_download_url(
            "12345678"sv,
            {"https", "example2.com", 321, file_server::DEFAULT_CONFIG.pubkey_hex, 54321, false});
    CHECK(url == "https://example2.com:321/file/12345678");

    // Omits the port when the scheme already implies it, so urls for a default-port server are
    // unchanged from every previous version
    url = file_server::generate_download_url(
            "abc123"sv,
            {"http", "example.com", 80, file_server::DEFAULT_CONFIG.pubkey_hex, 12345, false});
    CHECK(url == "http://example.com/file/abc123");

    url = file_server::generate_download_url(
            "abc123"sv,
            {"https", "example.com", 443, file_server::DEFAULT_CONFIG.pubkey_hex, 12345, false});
    CHECK(url == "https://example.com/file/abc123");

    // The default file server is unaffected
    url = file_server::generate_download_url("abc123"sv, file_server::DEFAULT_CONFIG);
    CHECK(url == fmt::format("http://{}/file/abc123", file_server::DEFAULT_CONFIG.host));
}

TEST_CASE("Download url port round trip", "[backend][session_file_server]") {
    // A self-hosted file server on a non-default port. Dropping the port here sent every recipient
    // to 80/443, which returns a response rather than an error -- so it surfaced as an
    // undecryptable attachment, far from its cause.
    constexpr auto custom_pubkey =
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000"sv;
    auto url = file_server::generate_download_url(
            "abc123"sv, {"http", "192.168.1.2", 8000, std::string{custom_pubkey}, 12345, false});
    CHECK(url == fmt::format("http://192.168.1.2:8000/file/abc123#p={}", custom_pubkey));

    auto parsed = file_server::parse_download_url(url);
    REQUIRE(parsed.has_value());
    CHECK(parsed->scheme == "http"sv);
    // The port is split OUT of the host: `to_request` builds a destination from the two separately,
    // so a host still carrying ":8000" would be a valid-looking hostname pointing nowhere.
    CHECK(parsed->host == "192.168.1.2"sv);
    REQUIRE(parsed->port.has_value());
    CHECK(*parsed->port == 8000);
    CHECK(parsed->file_id == "abc123"sv);
    REQUIRE(parsed->custom_pubkey_hex.has_value());
    CHECK(*parsed->custom_pubkey_hex == custom_pubkey);

    // No explicit port stays absent rather than being invented, so the caller's default applies
    parsed = file_server::parse_download_url("https://example.com/file/abc123"sv);
    REQUIRE(parsed.has_value());
    CHECK(parsed->host == "example.com"sv);
    CHECK_FALSE(parsed->port.has_value());

    // An IPv6 literal keeps every colon it came with: the trailing one is a port separator only
    // when a number follows it, which is the case the whole-string `parse_int` above exists to
    // distinguish.
    parsed = file_server::parse_download_url("http://[::1]/file/abc123"sv);
    REQUIRE(parsed.has_value());
    CHECK(parsed->host == "[::1]"sv);
    CHECK_FALSE(parsed->port.has_value());

    parsed = file_server::parse_download_url("http://[::1]:8000/file/abc123"sv);
    REQUIRE(parsed.has_value());
    CHECK(parsed->host == "[::1]"sv);
    REQUIRE(parsed->port.has_value());
    CHECK(*parsed->port == 8000);
}

TEST_CASE("Default file server onion pubkey", "[backend][session_file_server]") {
    // A download url carries the file server's ED25519 key, while an onion request needs the X25519
    // form, so every request derives one from the other. Pinned here because the two forms are 32
    // bytes either way: using the wrong one produces a perfectly well-formed key that simply never
    // decrypts, and the only symptom is the file server rejecting the request without naming a key.
    const auto derived = compute_x25519_pubkey(session::to_span<unsigned char>(
            oxenc::from_hex(file_server::DEFAULT_CONFIG.pubkey_hex)));

    CHECK(derived.hex() == "09324794aa9c11948189762d198c618148e9136ac9582068180661208927ef34");
}
