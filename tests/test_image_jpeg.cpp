#include <vips/vips.h>

#include <algorithm>
#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <session/image/vips.hpp>
#include <string>
#include <vector>

#include "../src/image/jpeg_encode.hpp"
#include "../src/image/vips_internal.hpp"

namespace detail = session::image::detail;
using detail::image_ptr;
using detail::Subsampling;

namespace {

// A deterministic stand-in for a photo: gradients for smooth areas plus noise for texture.  An
// alpha band, when asked for, is a plain gradient.
template <typename T = uint8_t>
image_ptr test_image(int w, int h, int bands, VipsInterpretation interpretation) {
    session::image::init();
    constexpr double max = sizeof(T) == 1 ? 255 : 65535;
    std::mt19937 rng{12345};
    std::normal_distribution<double> noise{0, max / 20};
    std::vector<T> px(size_t(w) * h * bands);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++)
            for (int b = 0; b < bands; b++) {
                double v = b == 0 ? max * x / w
                         : b == 1 ? max * y / h
                         : b == 2 ? max * (x + y) / (w + h)
                                  : max * (w - x) / w;
                if (b < 3)
                    v += noise(rng);
                px[(size_t(y) * w + x) * bands + b] = static_cast<T>(std::clamp(v, 0.0, max));
            }
    VipsImage* raw = vips_image_new_from_memory_copy(
            px.data(),
            px.size() * sizeof(T),
            w,
            h,
            bands,
            sizeof(T) == 1 ? VIPS_FORMAT_UCHAR : VIPS_FORMAT_USHORT);
    REQUIRE(raw);
    image_ptr raw_ptr{raw};
    VipsImage* out;
    REQUIRE(vips_copy(raw, &out, "interpretation", interpretation, nullptr) == 0);
    return image_ptr{out};
}

// Decoded in full before returning: an image from vips_image_new_from_buffer() reads the buffer
// lazily and does not copy it, and callers here pass temporaries.
image_ptr decode(const std::vector<std::byte>& jpeg) {
    VipsImage* img = vips_image_new_from_buffer(jpeg.data(), jpeg.size(), "", nullptr);
    if (!img)
        vips_error_clear();
    REQUIRE(img);
    image_ptr lazy{img};
    VipsImage* decoded = vips_image_copy_memory(img);
    REQUIRE(decoded);
    return image_ptr{decoded};
}

// Mean absolute difference per sample between two images of the same shape.
double mean_error(VipsImage* a, VipsImage* b) {
    VipsImage *diff, *abs;
    REQUIRE(vips_subtract(a, b, &diff, nullptr) == 0);
    image_ptr diff_ptr{diff};
    REQUIRE(vips_abs(diff, &abs, nullptr) == 0);
    image_ptr abs_ptr{abs};
    double avg;
    REQUIRE(vips_avg(abs, &avg, nullptr) == 0);
    return avg;
}

std::string chroma_subsampling(VipsImage* img) {
    const char* s = nullptr;
    REQUIRE(vips_image_get_string(img, "jpeg-chroma-subsample", &s) == 0);
    return s;
}

}  // namespace

TEST_CASE("JPEG encoding produces a progressive JPEG of the right shape", "[image][jpeg]") {
    INFO("encoder: " << detail::jpeg_encoder_name());
    auto img = test_image(300, 200, 3, VIPS_INTERPRETATION_sRGB);

    auto [subsampling, expected] = GENERATE(
            std::pair{Subsampling::yuv420, "4:2:0"}, std::pair{Subsampling::yuv444, "4:4:4"});
    auto jpeg = detail::encode_jpeg(img.get(), 80, subsampling);

    REQUIRE(jpeg.size() > 4);
    CHECK(jpeg[0] == std::byte{0xFF});
    CHECK(jpeg[1] == std::byte{0xD8});
    auto out = decode(jpeg);
    CHECK(out->Xsize == 300);
    CHECK(out->Ysize == 200);
    CHECK(out->Bands == 3);
    CHECK(chroma_subsampling(out.get()) == expected);
    int interlaced = 0;
    CHECK(vips_image_get_int(out.get(), "interlaced", &interlaced) == 0);
    CHECK(interlaced == 1);
}

TEST_CASE("JPEG encoding quality trades size for accuracy", "[image][jpeg]") {
    auto img = test_image(300, 200, 3, VIPS_INTERPRETATION_sRGB);
    auto low = detail::encode_jpeg(img.get(), 50);
    auto high = detail::encode_jpeg(img.get(), 90);
    CHECK(low.size() < high.size());
    CHECK(mean_error(img.get(), decode(low).get()) > mean_error(img.get(), decode(high).get()));
}

TEST_CASE("JPEG encoding converts its input", "[image][jpeg]") {
    SECTION("greyscale stays greyscale") {
        auto grey = test_image(120, 80, 1, VIPS_INTERPRETATION_B_W);
        auto out = decode(detail::encode_jpeg(grey.get(), 85));
        CHECK(out->Bands == 1);
        CHECK(mean_error(grey.get(), out.get()) < 8);
    }

    SECTION("16-bit input is brought down to 8 bits") {
        auto deep = test_image<uint16_t>(120, 80, 3, VIPS_INTERPRETATION_RGB16);
        auto out = decode(detail::encode_jpeg(deep.get(), 90));
        CHECK(out->Bands == 3);
        CHECK(out->BandFmt == VIPS_FORMAT_UCHAR);
        // The same picture made at 8 bits and encoded the same way: the 16-bit input should come
        // out as close to it as that does (a misread 16-bit buffer would be nowhere near).
        auto shallow = test_image(120, 80, 3, VIPS_INTERPRETATION_sRGB);
        auto shallow_out = decode(detail::encode_jpeg(shallow.get(), 90));
        CHECK(mean_error(shallow.get(), out.get()) ==
              Catch::Approx(mean_error(shallow.get(), shallow_out.get())).margin(0.5));
    }
}

TEST_CASE("JPEG encoding refuses what JPEG cannot hold", "[image][jpeg]") {
    auto rgba = test_image(64, 64, 4, VIPS_INTERPRETATION_sRGB);
    CHECK_THROWS_AS(detail::encode_jpeg(rgba.get(), 80), std::invalid_argument);

    auto rgb = test_image(64, 64, 3, VIPS_INTERPRETATION_sRGB);
    CHECK_THROWS_AS(detail::encode_jpeg(rgb.get(), 0), std::invalid_argument);
    CHECK_THROWS_AS(detail::encode_jpeg(rgb.get(), 101), std::invalid_argument);
}

TEST_CASE("JPEG encoding uses the configured encoder", "[image][jpeg]") {
#ifdef SESSION_ENABLE_JPEGLI
    CHECK(detail::jpeg_encoder_name() == "jpegli");
    // jpegli's output differs from what libvips' own libjpeg-turbo saver makes of the same input.
    auto img = test_image(300, 200, 3, VIPS_INTERPRETATION_sRGB);
    auto ours = detail::encode_jpeg(img.get(), 80);
    void* buf = nullptr;
    size_t len = 0;
    REQUIRE(vips_jpegsave_buffer(img.get(), &buf, &len, "Q", 80, nullptr) == 0);
    std::unique_ptr<void, decltype(&g_free)> theirs{buf, &g_free};
    CHECK((ours.size() != len || std::memcmp(ours.data(), buf, len) != 0));
#else
    CHECK(detail::jpeg_encoder_name() == "libjpeg-turbo");
#endif
}
