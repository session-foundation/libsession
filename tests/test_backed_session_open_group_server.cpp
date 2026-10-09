#include <fmt/format.h>

#include <catch2/catch_test_macros.hpp>
#include <session/network/backends/session_open_group_server.hpp>

#include "utils.hpp"

using namespace session::network;

TEST_CASE("Download url parsing", "[backend][session_open_group_server]") {

    auto parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "test"sv);
    CHECK(parsed_download_url->file_id == 123);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Strips a trailing forward slash from the file_id
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/123/"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "test"sv);
    CHECK(parsed_download_url->file_id == 123);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Identifies that the url wants stream-based decryption
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/123/#d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "test"sv);
    CHECK(parsed_download_url->file_id == 123);
    CHECK(parsed_download_url->wants_stream_decryption);

    // A valueless `d=` is NOT the stream-encryption fragment; see the equivalent case in
    // test_backend_session_file_server.cpp for why a client can end up writing it.
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/test/file/123/#d="sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->file_id == 123);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Maintains the room casing
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/room/TeST/file/123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room == "TeST"sv);
    CHECK(parsed_download_url->file_id == 123);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Falls back to the legacy room-less format (used by some older clients, e.g. Android),
    // leaving the room empty for the caller to populate from context
    parsed_download_url = open_group_server::parse_download_url("https://example.com/file/123"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room.empty());
    CHECK(parsed_download_url->file_id == 123);
    CHECK_FALSE(parsed_download_url->wants_stream_decryption);

    // Handles the legacy room-less format with a trailing slash and stream-decryption fragment
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/file/123/#d"sv);
    REQUIRE(parsed_download_url.has_value());
    CHECK(parsed_download_url->base_url == "https://example.com"sv);
    CHECK(parsed_download_url->room.empty());
    CHECK(parsed_download_url->file_id == 123);
    CHECK(parsed_download_url->wants_stream_decryption);

    // Doesn't have an issue with a url that isn't in the right format
    parsed_download_url =
            open_group_server::parse_download_url("https://example.com/test/test2/test3/5432"sv);
    CHECK_FALSE(parsed_download_url.has_value());
}

TEST_CASE("Download url generation", "[backend][session_open_group_server]") {
    auto url = open_group_server::generate_download_url(
            123,
            {"https://example.com",
             "test",
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             true});
    CHECK(url == "https://example.com/room/test/file/123#d");

    // Omits the stream encryption fragment when disabled
    url = open_group_server::generate_download_url(
            123,
            {"https://example.com",
             "test",
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             false});
    CHECK(url == "https://example.com/room/test/file/123");

    // Maintains the case of the room
    url = open_group_server::generate_download_url(
            123,
            {"https://example.com",
             "TeST",
             "0123456789abcdef0123456789abcdef00000000000000000000000000000000",
             true});
    CHECK(url == "https://example.com/room/TeST/file/123#d");
}