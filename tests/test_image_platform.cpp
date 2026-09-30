#include <libheif/heif.h>
#include <vips/vips.h>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <session/image/probe.hpp>

#include "../src/image/platform.hpp"
#include "image_fixtures.hpp"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <libheif/heif_items.h>
#include <oxenc/hex.h>

#include <filesystem>
#include <session/attachments.hpp>
#include <session/random.hpp>
#include <vector>
#endif

namespace image = session::image;
using image::Format;
using image_fixtures::heic_64x48;

TEST_CASE("can_decode reports what this build can decode", "[image][platform]") {
    for (auto f : {Format::jpeg, Format::png, Format::webp, Format::gif, Format::avif})
        CHECK(image::can_decode(f));

    bool libheif_hevc = heif_have_decoder_for_format(heif_compression_HEVC);
#ifdef __APPLE__
    CHECK(image::can_decode(Format::heic));
#else
    CHECK(image::can_decode(Format::heic) == libheif_hevc);
#endif
    image::Source src{heic_64x48};
    auto info = image::probe(src);
    REQUIRE(info);
    CHECK(info->decodable == image::can_decode(Format::heic));
    (void)libheif_hevc;
}

#ifdef __APPLE__

namespace {

using image::detail::image_ptr;

// Encodes a w x h gradient as HEIC with ImageIO: with an alpha band that fades out across it if
// `alpha`, and tagged with EXIF `orientation`.
std::vector<std::byte> make_heic(int w, int h, bool alpha, int orientation = 1) {
    std::vector<uint8_t> px(size_t(w) * h * 4);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            uint8_t* p = &px[(size_t(y) * w + x) * 4];
            uint8_t a = alpha ? uint8_t(255 * (w - x) / w) : 255;
            // Premultiplied, as CoreGraphics requires.
            p[0] = uint8_t(255 * x / w * a / 255);
            p[1] = uint8_t(255 * y / h * a / 255);
            p[2] = uint8_t(128 * a / 255);
            p[3] = a;
        }
    auto srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    auto ctx = CGBitmapContextCreate(
            px.data(),
            w,
            h,
            8,
            size_t(w) * 4,
            srgb,
            CGBitmapInfo(alpha ? kCGImageAlphaPremultipliedLast : kCGImageAlphaNoneSkipLast) |
                    kCGImageByteOrder32Big);
    auto img = CGBitmapContextCreateImage(ctx);

    auto out = CFDataCreateMutable(nullptr, 0);
    auto dest = CGImageDestinationCreateWithData(out, CFSTR("public.heic"), 1, nullptr);
    REQUIRE(dest);
    auto orient = CFNumberCreate(nullptr, kCFNumberIntType, &orientation);
    const void* keys[] = {kCGImagePropertyOrientation};
    const void* values[] = {orient};
    auto props = CFDictionaryCreate(
            nullptr,
            keys,
            values,
            1,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
    CGImageDestinationAddImage(dest, img, props);
    REQUIRE(CGImageDestinationFinalize(dest));

    auto* bytes = reinterpret_cast<const std::byte*>(CFDataGetBytePtr(out));
    std::vector<std::byte> heic{bytes, bytes + CFDataGetLength(out)};
    for (CFTypeRef r :
         {(CFTypeRef)props,
          (CFTypeRef)orient,
          (CFTypeRef)dest,
          (CFTypeRef)out,
          (CFTypeRef)img,
          (CFTypeRef)ctx,
          (CFTypeRef)srgb})
        CFRelease(r);
    return heic;
}

image_ptr decode(std::span<const std::byte> heic, uint32_t max_side = 0) {
    image::Source src{heic};
    return image::detail::platform_decode(src, Format::heic, max_side);
}

}  // namespace

TEST_CASE("ImageIO decodes HEIC", "[image][platform]") {
    SECTION("at full size") {
        auto img = decode(heic_64x48);
        CHECK(img->Xsize == 64);
        CHECK(img->Ysize == 48);
        CHECK(img->Bands == 3);
        CHECK(img->BandFmt == VIPS_FORMAT_UCHAR);
        CHECK(img->Type == VIPS_INTERPRETATION_sRGB);
        // The fixture is a flat grey of 90.
        double avg;
        REQUIRE(vips_avg(img.get(), &avg, nullptr) == 0);
        CHECK(avg == Catch::Approx(90).margin(4));
    }

    SECTION("scaled down to a longest side") {
        auto img = decode(heic_64x48, 32);
        CHECK(img->Xsize == 32);
        CHECK(img->Ysize == 24);
        // Never scaled up.
        auto same = decode(heic_64x48, 1000);
        CHECK(same->Xsize == 64);
    }

    SECTION("with its orientation applied") {
        auto heic = make_heic(64, 48, false, 6);
        auto img = decode(heic);
        CHECK(img->Xsize == 48);
        CHECK(img->Ysize == 64);
        image::Source src{heic};
        auto info = image::probe(src);
        REQUIRE(info);
        CHECK(info->width == 48);
        CHECK(info->height == 64);
    }

    SECTION("keeping alpha, unpremultiplied") {
        auto img = decode(make_heic(64, 48, true));
        REQUIRE(img->Bands == 4);
        CHECK(img->BandFmt == VIPS_FORMAT_UCHAR);
        // Opaque at the left edge, nearly transparent at the right.
        double left, right;
        VipsImage *band, *strip;
        REQUIRE(vips_extract_band(img.get(), &band, 3, nullptr) == 0);
        image_ptr alpha{band};
        REQUIRE(vips_extract_area(alpha.get(), &strip, 0, 0, 4, 48, nullptr) == 0);
        image_ptr l{strip};
        REQUIRE(vips_extract_area(alpha.get(), &strip, 60, 0, 4, 48, nullptr) == 0);
        image_ptr r{strip};
        REQUIRE(vips_avg(l.get(), &left, nullptr) == 0);
        REQUIRE(vips_avg(r.get(), &right, nullptr) == 0);
        CHECK(left > 240);
        CHECK(right < 30);
    }

    SECTION("from an encrypted source") {
        std::filesystem::path path =
                std::filesystem::temp_directory_path() /
                ("libsession-platform-test-" + oxenc::to_hex(session::random::random(8)));
        auto seed = session::random::random(32);
        auto key = session::attachment::encrypt(
                std::as_bytes(std::span{seed}),
                heic_64x48,
                session::attachment::Domain::ATTACHMENT,
                path);
        image::Source src{path, key};
        auto img = image::detail::platform_decode(src, Format::heic, 0);
        CHECK(img->Xsize == 64);
        std::filesystem::remove(path);
    }
}

TEST_CASE("probe finds the codec of a gridded HEIC through its tiles", "[image][platform]") {
    // Large enough that ImageIO writes it as a grid of tiles, as the camera does.
    auto heic = make_heic(2000, 1500, false);

    // Make sure this really is a grid, or the test would prove nothing.
    std::unique_ptr<heif_context, decltype(&heif_context_free)> ctx{
            heif_context_alloc(), &heif_context_free};
    REQUIRE(heif_context_read_from_memory_without_copy(ctx.get(), heic.data(), heic.size(), nullptr)
                    .code == heif_error_Ok);
    heif_image_handle* handle;
    REQUIRE(heif_context_get_primary_image_handle(ctx.get(), &handle).code == heif_error_Ok);
    auto type = heif_item_get_item_type(ctx.get(), heif_image_handle_get_item_id(handle));
    heif_image_handle_release(handle);
    INFO("primary item type 0x" << std::hex << type);
    REQUIRE(type == 0x67726964u);  // 'grid'

    image::Source src{heic};
    auto info = image::probe(src);
    REQUIRE(info);
    CHECK(info->format == Format::heic);
    CHECK(info->width == 2000);
    CHECK(info->height == 1500);
    CHECK(info->decodable);
    auto img = image::detail::platform_decode(src, Format::heic, 500);
    CHECK(img->Xsize == 500);
    CHECK(img->Ysize == Catch::Approx(375).margin(1));
}

#endif
