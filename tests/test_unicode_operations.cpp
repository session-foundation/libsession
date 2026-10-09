#include <catch2/catch_test_macros.hpp>
#include <session/util.hpp>

TEST_CASE("utf16_truncate works", "[util]") {
    // Given simple ASCII string requesting all codepoints, returns the whole string
    CHECK(session::utf16_truncate(u"hello_world", 11) == u"hello_world");

    // Given zero codepoints requested, returns an empty string
    CHECK(session::utf16_truncate(u"hello_world", 0) == u"");

    // 🎂 is a surrogate pair counting as a single codepoint, so all 11 codepoints is the whole
    // (12-code-unit) string
    CHECK(session::utf16_truncate(u"hello🎂world", 11) == u"hello🎂world");

    // Requesting 6 codepoints keeps "hello🎂" without splitting the surrogate pair
    CHECK(session::utf16_truncate(u"hello🎂world", 6) == u"hello🎂");

    // Requesting 5 codepoints keeps "hello"
    CHECK(session::utf16_truncate(u"hello🎂world", 5) == u"hello");

    // Requesting more codepoints than present returns the whole string
    CHECK(session::utf16_truncate(u"hello🎂world", 13) == u"hello🎂world");
}

TEST_CASE("utf16_count works", "[util]") {
    CHECK(session::utf16_count(u"hello_world") == 11);
    CHECK(session::utf16_count(u"hello🎂world") == 11);
    CHECK(session::utf16_count(u"🎂🎉🎈🎁") == 4);
    CHECK(session::utf16_count(u"") == 0);
}
