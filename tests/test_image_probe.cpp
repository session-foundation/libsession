#include <libheif/heif.h>
#include <oxenc/base64.h>
#include <vips/vips.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <filesystem>
#include <fstream>
#include <memory>
#include <session/attachments.hpp>
#include <session/image/probe.hpp>
#include <session/image/vips.hpp>
#include <session/random.hpp>
#include <string>
#include <vector>

#include "../src/image/vips_internal.hpp"
#include "image_fixtures.hpp"
#include "utils.hpp"

namespace image = session::image;
using Catch::Matchers::Message;
using image::Format;
using image::detail::image_ptr;
using image_fixtures::avif_64x48;
using image_fixtures::heic_64x48;

namespace {

// A w x h image with `bands` bands; `frames` of them stacked vertically, as libvips holds
// animation.  Each frame is a different shade: animation encoders merge a frame identical to the
// one before it into a longer one.
image_ptr make_image(int w, int h, int bands = 3, int frames = 1) {
    image::init();
    std::vector<VipsImage*> shades;
    for (int i = 0; i < frames; i++) {
        VipsImage *black, *shade;
        REQUIRE(vips_black(&black, w, h, "bands", bands, nullptr) == 0);
        image_ptr black_ptr{black};
        REQUIRE(vips_linear1(black, &shade, 1.0, 100.0 + 30 * i, "uchar", TRUE, nullptr) == 0);
        shades.push_back(shade);
    }
    VipsImage* img;
    int rc = vips_arrayjoin(shades.data(), &img, frames, "across", 1, nullptr);
    for (auto* s : shades)
        g_object_unref(s);
    REQUIRE(rc == 0);
    image_ptr out{img};
    if (bands >= 3) {
        VipsImage* srgb;
        REQUIRE(vips_copy(img, &srgb, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr) == 0);
        out.reset(srgb);
    }
    if (frames > 1)
        vips_image_set_int(out.get(), "page-height", h);
    return out;
}

std::vector<std::byte> save(VipsImage* img, const char* suffix) {
    void* buf = nullptr;
    size_t len = 0;
    REQUIRE(vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr) == 0);
    std::vector<std::byte> out{static_cast<std::byte*>(buf), static_cast<std::byte*>(buf) + len};
    g_free(buf);
    return out;
}

std::optional<image::Info> probe_bytes(std::span<const std::byte> data) {
    image::Source src{data};
    return image::probe(src);
}

// A copy of `data` with every occurrence of the 4-byte `from` replaced by `to`.
std::vector<std::byte> replace4(
        std::span<const std::byte> data, std::string_view from, std::string_view to) {
    std::vector<std::byte> out{data.begin(), data.end()};
    auto f = std::as_bytes(std::span{from});
    for (auto it = out.begin(); (it = std::search(it, out.end(), f.begin(), f.end())) != out.end();)
        it = std::copy_n(reinterpret_cast<const std::byte*>(to.data()), 4, it);
    return out;
}

struct temp_file {
    std::filesystem::path path =
            std::filesystem::temp_directory_path() /
            ("libsession-probe-test-" + oxenc::to_hex(session::random::random(8)));
    ~temp_file() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    void write(std::span<const std::byte> data) const {
        std::ofstream out{path, std::ios::binary | std::ios::trunc};
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
};

}  // namespace

TEST_CASE("probe reads each accepted format's header", "[image][probe]") {
    SECTION("JPEG") {
        auto info = probe_bytes(save(make_image(64, 48).get(), ".jpg"));
        REQUIRE(info);
        CHECK(info->format == Format::jpeg);
        CHECK(info->width == 64);
        CHECK(info->height == 48);
        CHECK(info->frames == 1);
        CHECK(info->orientation == 1);
        CHECK_FALSE(info->has_alpha);
        CHECK(info->decodable);
    }

    SECTION("PNG with alpha") {
        auto info = probe_bytes(save(make_image(20, 10, 4).get(), ".png"));
        REQUIRE(info);
        CHECK(info->format == Format::png);
        CHECK(info->width == 20);
        CHECK(info->height == 10);
        CHECK(info->has_alpha);
    }

    SECTION("animated WebP and GIF report their frames, and one frame's size") {
        for (const char* suffix : {".webp", ".gif"}) {
            INFO(suffix);
            auto info = probe_bytes(save(make_image(30, 20, 3, 4).get(), suffix));
            REQUIRE(info);
            CHECK(info->format ==
                  (suffix == std::string_view{".webp"} ? Format::webp : Format::gif));
            CHECK(info->width == 30);
            CHECK(info->height == 20);
            CHECK(info->frames == 4);
            CHECK(info->animated());
        }
    }

    SECTION("AVIF") {
        auto info = probe_bytes(avif_64x48);
        REQUIRE(info);
        CHECK(info->format == Format::avif);
        CHECK(info->width == 64);
        CHECK(info->height == 48);
        CHECK(info->frames == 1);
        CHECK(info->decodable);
    }

    SECTION("HEIC is recognised whether or not it can be decoded") {
        auto info = probe_bytes(heic_64x48);
        REQUIRE(info);
        CHECK(info->format == Format::heic);
        CHECK(info->width == 64);
        CHECK(info->height == 48);
#ifdef __APPLE__
        CHECK(info->decodable);
#else
        CHECK(info->decodable == (heif_have_decoder_for_format(heif_compression_HEVC) != 0));
#endif
    }
}

TEST_CASE("probe reports display dimensions after EXIF orientation", "[image][probe]") {
    auto img = make_image(64, 32);
    vips_image_set_int(img.get(), "orientation", 6);
    auto info = probe_bytes(save(img.get(), ".jpg"));
    REQUIRE(info);
    CHECK(info->orientation == 6);
    // Stored 64 wide, but displayed rotated a quarter turn.
    CHECK(info->width == 32);
    CHECK(info->height == 64);
}

TEST_CASE("probe refuses what we do not accept", "[image][probe]") {
    image::init();
    std::string_view text = "just some text, which is not an image at all";
    CHECK_FALSE(probe_bytes(std::as_bytes(std::span{text})));
    std::string_view svg = R"(<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"/>)";
    CHECK_FALSE(probe_bytes(std::as_bytes(std::span{svg})));
    std::string_view matrix = "2 2\n0 0\n0 0\n";
    CHECK_FALSE(probe_bytes(std::as_bytes(std::span{matrix})));

    // A HEIF file's codec is the item type of its primary image: the same file claiming JPEG or
    // uncompressed pixels instead of HEVC is HEIF that no other client would decode.
    CHECK(probe_bytes(heic_64x48));
    CHECK_FALSE(probe_bytes(replace4(heic_64x48, "hvc1", "jpeg")));
    CHECK_FALSE(probe_bytes(replace4(heic_64x48, "hvc1", "unci")));
}

TEST_CASE("probe reports oversized images rather than refusing them", "[image][probe]") {
    auto jpeg = save(make_image(64, 48).get(), ".jpg");
    // The baseline frame header (SOF0) holds the height then the width, 16 bits each, after its
    // length and sample precision.
    const std::array<std::byte, 2> sof0{std::byte{0xFF}, std::byte{0xC0}};
    auto sof = std::search(jpeg.begin(), jpeg.end(), sof0.begin(), sof0.end());
    REQUIRE(sof != jpeg.end());
    for (int i : {5, 7}) {
        sof[i] = std::byte{20000 >> 8};
        sof[i + 1] = std::byte{20000 & 0xff};
    }
    auto info = probe_bytes(jpeg);
    REQUIRE(info);
    CHECK(info->width == 20000);
    CHECK(info->height == 20000);
    CHECK_FALSE(info->within_pixel_limits(false));

    image::Info anim{
            .format = Format::gif, .width = 4000, .height = 4000, .frames = 20, .orientation = 1};
    CHECK(anim.within_pixel_limits(false));
    // 320 million pixels across its frames: past the total if every frame is to be decoded.
    CHECK_FALSE(anim.within_pixel_limits(true));
}

TEST_CASE("probe reads plain and encrypted files", "[image][probe]") {
    auto png = save(make_image(40, 30).get(), ".png");

    SECTION("plain file") {
        temp_file f;
        f.write(png);
        image::Source src{f.path};
        CHECK(src.size() == png.size());
        auto info = image::probe(src);
        REQUIRE(info);
        CHECK(info->format == Format::png);
        CHECK(info->width == 40);
        // A source can be read again.
        CHECK(image::probe(src));
    }

    auto seed = session::random::random(32);
    temp_file f;
    auto key = session::attachment::encrypt(
            std::as_bytes(std::span{seed}), png, session::attachment::Domain::ATTACHMENT, f.path);

    SECTION("encrypted file") {
        image::Source src{f.path, key};
        CHECK(src.size() == png.size());
        auto info = image::probe(src);
        REQUIRE(info);
        CHECK(info->format == Format::png);
        CHECK(info->width == 40);
        CHECK(info->height == 30);
        CHECK(image::probe(src));
    }

    SECTION("wrong key") {
        key[0] ^= std::byte{1};
        CHECK_THROWS_AS((image::Source{f.path, key}), std::runtime_error);
    }
}

TEST_CASE("probe throws a decryption error rather than calling it not an image", "[image][probe]") {
    // A text chunk ahead of the pixel data, so that reading the header needs the second of the
    // encrypted file's 32kiB chunks; the source's own construction only decrypts the first.  The
    // text is random because some PNG savers compress comments.
    auto img = make_image(40, 30);
    auto padding = oxenc::to_base64(session::random::random(45000));
    vips_image_set_string(img.get(), "png-comment-0-padding", padding.c_str());
    auto png = save(img.get(), ".png");
    REQUIRE(png.size() > 40000);

    auto seed = session::random::random(32);
    temp_file f;
    auto key = session::attachment::encrypt(
            std::as_bytes(std::span{seed}), png, session::attachment::Domain::ATTACHMENT, f.path);
    {
        std::fstream io{f.path, std::ios::binary | std::ios::in | std::ios::out};
        auto pos = 1 + session::attachment::ENCRYPT_HEADER +
                   session::attachment::ENCRYPTED_CHUNK_TOTAL + 100;
        io.seekg(pos);
        char c = static_cast<char>(io.get());
        io.seekp(pos);
        io.put(static_cast<char>(c ^ 1));
    }

    image::Source src{f.path, key};
    CHECK_THROWS_MATCHES(
            image::probe(src),
            std::runtime_error,
            Message("Attachment decryption failed: invalid key or corrupted data"));
}
