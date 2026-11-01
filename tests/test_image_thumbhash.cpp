#include <oxenc/hex.h>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cmath>
#include <set>
#include <vector>

#include "../src/image/det_trig.hpp"
#include "session/image/thumbhash.hpp"

using namespace session::image;
using namespace std::literals;

namespace {

// A synthetic image with enough structure in every channel that all the DCT terms are exercised:
// a diagonal luminance ramp, opposing red/blue gradients, and a green blob.
std::vector<std::byte> test_image(int w, int h, bool alpha) {
    std::vector<std::byte> px(size_t(w) * h * 4);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            double fx = double(x) / std::max(1, w - 1), fy = double(y) / std::max(1, h - 1);
            double blob = std::exp(-8 * ((fx - 0.3) * (fx - 0.3) + (fy - 0.7) * (fy - 0.7)));
            auto set = [&](int c, double v) {
                px[(size_t(y) * w + x) * 4 + c] =
                        std::byte(uint8_t(std::clamp(v, 0.0, 1.0) * 255 + 0.5));
            };
            set(0, 0.9 * fx + 0.05);
            set(1, blob);
            set(2, 0.9 * (1 - fy) + 0.05);
            // A soft circular cutout, so the alpha DCT has something to encode.
            set(3, alpha ? std::clamp(1.6 - 3.0 * std::hypot(fx - 0.5, fy - 0.5), 0.0, 1.0) : 1.0);
        }
    return px;
}

}  // namespace

// det_trig replaces std::cos with a hand-written Taylor series, so the coefficient table is a
// transcription that nothing else would catch if it were wrong: a bad term still produces smooth,
// plausible-looking output, just with the wrong values baked into every hash.  Check it against
// libm over exactly the arguments the DCT uses.  The tolerance is far looser than the ~4e-15 the
// two genuinely differ by (libm is handed a thrice-rounded angle) and far tighter than any
// consequential typo, which would show up at 1e-5 or worse.
TEST_CASE("det_trig cosine agrees with libm", "[image][thumbhash][det_trig]") {
    using session::image::detail::cos_dct;
    using session::image::detail::cos_pi;

    double worst = 0;
    for (int n = 1; n <= 100; n++)
        for (int k = 0; k <= 6; k++)
            for (int i = 0; i < n; i++)
                worst = std::max(
                        worst, std::abs(cos_dct(k, i, n) - std::cos(M_PI / n * k * (i + 0.5))));
    CHECK(worst < 1e-13);

    // Exact values the reduction must land on, covering every branch: each octant, the sign flip
    // past pi/2, and wrap-around of the integer reduction.
    CHECK(cos_pi(0, 7) == 1.0);
    CHECK(cos_pi(7, 7) == -1.0);
    CHECK(cos_pi(14, 7) == 1.0);                              // 2pi
    CHECK(cos_pi(-7, 7) == -1.0);                             // negative numerator
    CHECK(cos_pi(700, 7) == 1.0);                             // many periods
    CHECK(cos_pi(1, 2) == Catch::Approx(0.0).margin(1e-16));  // pi/2
    CHECK(cos_pi(1, 3) == Catch::Approx(0.5));                // pi/3
    CHECK(cos_pi(2, 3) == Catch::Approx(-0.5));               // 2pi/3
    CHECK(cos_pi(1, 4) == Catch::Approx(std::sqrt(0.5)));     // pi/4, the branch boundary
    CHECK(cos_pi(3, 4) == Catch::Approx(-std::sqrt(0.5)));
    CHECK(cos_pi(1, 6) == Catch::Approx(std::sqrt(3.0) / 2));  // pi/6, cos branch
    CHECK(cos_pi(5, 6) == Catch::Approx(-std::sqrt(3.0) / 2));
}

TEST_CASE("thumbhash round-trip", "[image][thumbhash]") {
    for (auto alpha : {false, true}) {
        for (auto [w, h] : {std::pair{32, 32}, {64, 48}, {48, 64}, {100, 100}, {7, 3}, {1, 1}}) {
            auto px = test_image(w, h, alpha);
            auto hash = thumbhash::encode(px, w, h);

            CHECK(hash.size() >= 5);
            CHECK(hash.size() <= thumbhash::max_hash_size);
            // Alpha is only carried when some pixel is actually translucent.
            CHECK(((std::to_integer<uint8_t>(hash[2]) & 0x80) != 0) == alpha);

            auto img = thumbhash::decode_unsized(hash, 32);
            CHECK(img.rgba.size() == size_t(img.width) * img.height * 4);
            CHECK(img.width >= 1);
            CHECK(img.height >= 1);
            CHECK(std::max(img.width, img.height) == 32);

            auto exact = thumbhash::decode(hash, 20, 10);
            CHECK(exact.width == 20);
            CHECK(exact.height == 10);
            CHECK(exact.rgba.size() == 20 * 10 * 4);
        }
    }
}

namespace {

// Per-channel mean of a decoded image.
std::array<double, 4> channel_means(const thumbhash::image& im) {
    std::array<double, 4> sum{};
    size_t n = size_t(im.width) * im.height;
    for (size_t i = 0; i < n; i++)
        for (int c = 0; c < 4; c++)
            sum[c] += std::to_integer<uint8_t>(im.rgba[i * 4 + c]);
    for (auto& v : sum)
        v /= double(n);
    return sum;
}

}  // namespace

TEST_CASE("thumbhash decode is resolution independent", "[image][thumbhash]") {
    auto hash = thumbhash::encode(test_image(64, 48, false), 64, 48);

    // The DCT basis is continuous, so decoding at different resolutions samples the same
    // underlying surface: the overall colour should not shift with the output grid.
    auto coarse = channel_means(thumbhash::decode(hash, 16, 12));
    auto fine = channel_means(thumbhash::decode(hash, 160, 120));
    for (int c = 0; c < 4; c++)
        CHECK(std::abs(coarse[c] - fine[c]) < 2.0);
}

TEST_CASE("thumbhash average colour matches the decoded mean", "[image][thumbhash]") {
    for (auto alpha : {false, true}) {
        auto hash = thumbhash::encode(test_image(40, 40, alpha), 40, 40);
        auto avg = thumbhash::average_rgba(hash);
        // average_rgba reads the DC terms, which are the mean of the image; the AC terms very
        // nearly integrate away over the whole grid, so the decoded mean should land close by.
        // Clamping and the 1.25x chroma boost keep it from being exact.
        auto mean = channel_means(thumbhash::decode(hash, 32, 32));
        for (int c = 0; c < 4; c++)
            CHECK(std::abs(double(std::to_integer<uint8_t>(avg[c])) - mean[c]) <= 24.0);
    }
}

TEST_CASE("thumbhash aspect ratio", "[image][thumbhash]") {
    auto wide = thumbhash::encode(test_image(96, 32, false), 96, 32);
    auto tall = thumbhash::encode(test_image(32, 96, false), 32, 96);
    auto square = thumbhash::encode(test_image(48, 48, false), 48, 48);
    CHECK(thumbhash::component_aspect_ratio(wide) > 1.5);
    CHECK(thumbhash::component_aspect_ratio(tall) < 0.67);
    CHECK(thumbhash::component_aspect_ratio(square) == 1.0);

    // decode_unsized() should follow the component ratio.
    auto w = thumbhash::decode_unsized(wide, 32);
    CHECK(w.width == 32);
    CHECK(w.height < 32);
}

// component_aspect_ratio() reports the DCT component counts, not the image's shape, so it can only
// ever return 7/n for n in 1..7 (or 5/n with alpha) and saturates beyond that.  Pinned here so the
// limitation stays visible rather than being discovered in a client: a 1000x637 photo scaled to
// 100x64 by the sender comes back as 7/4, and anything wider than 7:1 comes back as exactly 7.
TEST_CASE("thumbhash component ratio is not an aspect ratio", "[image][thumbhash]") {
    struct {
        int w, h;
        double expected;
    } const cases[] = {
            {100, 64, 7.0 / 4},  // a 1000x637 source: true 1.570
            {100, 56, 7.0 / 4},  // 1920x1080: true 1.778
            {100, 75, 7.0 / 5},  // 4032x3024: true 1.333
            {100, 25, 7.0 / 2},  // 2000x500: true 4.0
            {100, 100, 1.0},     //
            {64, 100, 4.0 / 7},  // portrait
            {100, 10, 7.0},      // 1000x100 banner: true 10.0, saturated
            {100, 1, 7.0},       // 100:1, still 7.0
    };
    for (const auto& c : cases) {
        auto hash = thumbhash::encode(test_image(c.w, c.h, false), c.w, c.h);
        INFO(c.w << "x" << c.h);
        CHECK(thumbhash::component_aspect_ratio(hash) == Catch::Approx(c.expected));
    }

    // The whole representable set, so a change to it cannot slip through silently.
    //
    // The grid stops at 20 because the stored counts are round(7 * w / max(w, h)) -- a function of
    // the shape alone -- so every reachable bucket already appears within it, while encode cost is
    // quadratic in the dimensions and, where libm has to emulate fma, ruinously so.
    std::set<double> seen;
    for (int w = 1; w <= 20; w++)
        for (int h = 1; h <= 20; h++)
            seen.insert(thumbhash::component_aspect_ratio(
                    thumbhash::encode(test_image(w, h, false), w, h)));
    CHECK(seen.size() == 13);
    CHECK(*seen.begin() == Catch::Approx(1.0 / 7));
    CHECK(*seen.rbegin() == Catch::Approx(7.0));

    // Callers who know the real size should bypass it entirely.
    auto hash = thumbhash::encode(test_image(100, 64, false), 100, 64);
    auto img = thumbhash::decode(hash, 32, 20);  // the true 1000x637 shape
    CHECK(img.width == 32);
    CHECK(img.height == 20);
}

// A hash's length is a pure function of its header, so a carrier storing peer-supplied values can
// check exact structural validity rather than a loose cap -- a cap would pass a blob of the right
// size but arbitrary content.
TEST_CASE("thumbhash validity is exact, not a length cap", "[image][thumbhash]") {
    // Small shapes suffice: length depends only on the alpha flag and the stored component count,
    // so all six reachable lengths already appear within 20x20, and encode cost is quadratic in
    // the dimensions.
    std::set<size_t> lengths;
    for (auto alpha : {false, true})
        for (int w = 1; w <= 20; w++)
            for (int h = 1; h <= 20; h++) {
                auto hash = thumbhash::encode(test_image(w, h, alpha), w, h);
                INFO(w << "x" << h << (alpha ? " rgba" : " rgb"));
                CHECK(thumbhash::valid(hash));
                CHECK(thumbhash::expected_size(hash) == hash.size());
                CHECK(hash.size() <= thumbhash::max_hash_size);
                lengths.insert(hash.size());

                // One byte short or one byte long is not the length its own header demands.
                CHECK_FALSE(thumbhash::valid(std::span{hash}.first(hash.size() - 1)));
                auto padded = hash;
                padded.push_back(std::byte{0});
                CHECK_FALSE(thumbhash::valid(padded));
            }

    // Only six lengths are reachable at all.
    CHECK(lengths == std::set<size_t>{17, 19, 21, 23, 24, 25});

    // Too short to hold a header at all.
    for (size_t n = 0; n < 5; n++)
        CHECK(thumbhash::expected_size(std::vector<std::byte>(n)) == std::nullopt);
    // Header says alpha, but the alpha DC byte is missing.
    std::vector<std::byte> alpha_hdr(5, std::byte{0});
    alpha_hdr[2] = std::byte{0x80};
    CHECK(thumbhash::expected_size(alpha_hdr) == std::nullopt);

    // A component count of 0 is not something any encoder emits, but it is one bit-field a peer
    // controls, and the decoder's max(3, ...) clamp would otherwise wave it through while
    // component_aspect_ratio -- which reads the field unclamped -- rejects it.  valid() has to
    // agree with the rest of the API about what it will accept, or it is not a trust boundary.
    for (auto [w, h] : {std::pair{100, 43}, {43, 100}}) {
        auto hash = thumbhash::encode(test_image(w, h, false), w, h);
        REQUIRE(thumbhash::valid(hash));
        hash[3] &= std::byte{0xf8};
        INFO(w << "x" << h << " with the component count zeroed");
        CHECK_FALSE(thumbhash::valid(hash));
        CHECK(thumbhash::expected_size(hash) == std::nullopt);
    }
}

TEST_CASE("thumbhash rejects bad input", "[image][thumbhash]") {
    auto px = test_image(8, 8, false);
    CHECK_THROWS_AS(thumbhash::encode(px, 8, 7), std::invalid_argument);  // size mismatch
    CHECK_THROWS_AS(thumbhash::encode(px, 0, 8), std::invalid_argument);  // zero dimension
    CHECK_THROWS_AS(thumbhash::encode(test_image(101, 1, false), 101, 1), std::invalid_argument);

    auto hash = thumbhash::encode(px, 8, 8);
    auto prefix = [&hash](size_t n) { return std::span{hash}.first(n); };
    CHECK_THROWS_AS(thumbhash::decode(prefix(4), 8, 8), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode({}, 8, 8), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode(hash, 0, 4), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode_unsized(hash, 0), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode_unsized(prefix(4)), std::invalid_argument);
    // Truncated in the middle of the AC nibbles.
    CHECK_THROWS_AS(thumbhash::decode(prefix(6), 8, 8), std::invalid_argument);
}

// These vectors pin the floating-point behaviour of the encoder.  A thumbhash is sent to other
// people, so if it varied with the platform's libm or with whether the compiler contracted a*b+c
// into an FMA, it would leak a bit about which client produced it.  src/image/det_trig.hpp removes
// both sources; this test is the backstop that makes a build which reintroduces one fail loudly
// instead of silently fingerprinting users.
//
// If this fails on a new platform, do not regenerate the vectors: find out which assumption broke
// (most likely the rounding mode, or x87 excess precision from a non-SSE2 x86 build).
TEST_CASE("thumbhash is bit-reproducible", "[image][thumbhash]") {
    struct {
        int w, h;
        bool alpha;
        std::string_view expected;
    } const vectors[] = {
            {32, 32, false, "1b67067f262062763f9a885289d879678789670777909a09"sv},
            {64, 48, false, "1b67067da62062763f9a885289d87976767007a999"sv},
            {48, 64, false, "1b67067d2620623f9a2895d879769878767007a999"sv},
            {32, 32, true, "9d3782250a2617b138d871efbd777007b99808688888808968"sv},
            {64, 48, true, "9d3782248c3717a138d871ef7d0777908b8980868808988806"sv},
            {100, 100, false, "1b67067f261061763f9a885189e879678789670777909a09"sv},
            {17, 5, true, "9d378219883506b037d883777007b98828788888808a78"sv},
            {1, 1, false, "d5102ad70708f808888888808f8088f80888808ff8088800"sv},
    };
    for (const auto& v : vectors) {
        auto hash = thumbhash::encode(test_image(v.w, v.h, v.alpha), v.w, v.h);
        INFO(v.w << "x" << v.h << (v.alpha ? " rgba" : " rgb"));
        CHECK(oxenc::to_hex(hash) == v.expected);
    }
}

// The vectors above pin the encoder only.  Everything else that touches the decoder checks it
// against itself -- resolution independence compares two decodes, and the average-colour test
// compares two quantities that both derive from the same DC terms -- so a decoder that produced
// consistently wrong pixels would pass the whole suite.  Pin its actual output too.
//
// Decoded at 8x6 so the expected bytes stay readable; that is enough pixels to exercise every
// branch of the reconstruction, including the alpha channel on the RGBA entries.
TEST_CASE("thumbhash decoder output is pinned", "[image][thumbhash]") {
    struct {
        int w, h;
        bool alpha;
        std::string_view expected;
    } const vectors[] = {
            {32,
             32,
             false,
             "1200ebff2d0cfaff4819faff6715f4ff9001efffbc00ecffed00f5ffff00ffff0017beff1a33d1ff"
             "3840d5ff583aceff8122c9ffad00c5ffda00cafff800d1ff005f8eff1b80a8ff3c8cadff5a7da3ff"
             "805c99ffaa3092ffd50b93fff20099ff009859ff26bd79ff4dc983ff6ab377ff8f8869ffb5515cff"
             "df255bfffd1061ff01ad28ff31d24aff5adb54ff7ac149ffa0913bffc6532dfff0232bffff0d32ff"
             "008a00ff12aa05ff39af0eff5d9506ff8a6900ffb82f00ffe70100ffff0004ff"sv},
            {64,
             48,
             false,
             "1100eaff2c0af8ff4617f9ff6614f3ff9001efffbd00edffec00f4ffff00feff001ac2ff1e36d5ff"
             "3b44d8ff5a3cd0ff8223c9ffae00c5ffdc00ccfffb00d4ff005a89ff177ca3ff3989abff577ba1ff"
             "7d5996ffa72d8fffd30891fff00097ff009c5dff2ac17cff50cc86ff6eb67aff928c6dffb95560ff"
             "e1285efffe1162ff00ac27ff2fcf47ff56d751ff76bd46ff9d8e39ffc4522bffee222affff0c31ff"
             "008a00ff13ab06ff3bb110ff5f9708ff8b6a00ffb82f00ffe70200ffff0005ff"sv},
            {48,
             64,
             false,
             "1400edff2b09f7ff491afcff6715f4ff8d00ecffbe00eeffef00f7ffff00feff0018bfff1730ceff"
             "3a43d7ff5a3cd0ff7e20c6ffad00c4ffdb00cbfff800d0ff006190ff167ba3ff3e8eafff5d80a7ff"
             "7e5a97ffa92f91ffd60c94fff20099ff009b5cff21b873ff4dc983ff6db67aff8c8666ffb6515dff"
             "e1275dfffb0f60ff04b12cff2ccd45ff5bdc56ff7cc34cff9c8e38ffc7542efff3262effff0b30ff"
             "008b00ff0da501ff3cb211ff609809ff856400ffb82f00ffeb0500ffff0002ff"sv},
            {32,
             32,
             true,
             "6c559e096d559c2d71549a49784f9850824696538e3b9649983196169e2a9700696195396a619366"
             "6e609190755b8fa27f528ea98a478e9b953c8e629b358f2365738649677385816b7183b9726b81d3"
             "7c6280da885680c6924b8185984582426681774d678176886c7f74c2737973db7d6f73de896373c6"
             "935774859a5075426a896c2d6c886b6570856999777f68ab827568ab8d686997985c6a5e9e556b22"
             "6e8b66006f8a650f7487643d7b81634b8676634b9269643d9c5d650ea3566600"sv},
            {64,
             48,
             true,
             "6b569e006d559c2171539a4c794e98568543965b9336964b9f299600a62197006664953368639378"
             "6d6191b7755b8fd181508edb8e438ec69b368e71a22e8f126177864b6377859f687483f4706e81ff"
             "7c6280ff8a5480ff964781a69e3f824160877751628676aa678374ff6f7c73ff7c7073ff8a6273ff"
             "975474a59e4c7541648f6c22668e6b766b8a69c4738368df807768df8e6769c09b596a6ba3516b11"
             "689166006a9065006f8c643a7884634e8477634e93686439a05a6500a7516600"sv},
            {100,
             100,
             false,
             "0e00e7ff2d0bf9ff4a1bfdff6a18f7ff9002efffbb00ebffeb00f3ffff00ffff0011b9ff1831cfff"
             "3942d6ff5a3bd0ff8022c8ffaa00c2ffd700c7fff600cfff005c8bff1b80a7ff3f90b1ff5d81a7ff"
             "815d9bffa92f91ffd40a92fff20099ff009758ff29c07cff53d089ff71b97eff938c6dffb8535eff"
             "e1285dffff1464ff00ab26ff32d34bff5ee059ff7fc64effa2933effc6542dfff0232bffff0f33ff"
             "008200ff0ea601ff38af0eff5d9506ff886600ffb32a00ffe20000ffff0001ff"sv},
            {17,
             5,
             true,
             "6e5b96006f5b940c725a931878569120804f902689469018913e9000963890006e628f266f628e49"
             "72618c73775d8a927f568a9c894d898391448a42963f8a066d6e84486e6d8381716c81c9776780fb"
             "7f607fff885780dc914e80879648813e6d79794e6e78788b727677d7777276ff806a75ff896075dd"
             "915776869651773e6e8170156f807047727e6e8078796da081716da08a676e7d935d6f3c98587005"
             "6e856c0070846b0073826a07797c6919817469188b6a6a0693606b00995a6c00"sv},
            {1,
             1,
             false,
             "ffff00ffffff00ff000000ff9a8affff8475ffff000000ffffff00ff4a7600ff707b00ff000000ff"
             "000000ff0000ffff0000ffff000000ff000000ff293b00ff5547d8ff0000ffff0000ffffffffffff"
             "ffffffff0000ffff0000ffff1007f6ff3a2fe7ff0000ffff0000ffffffffffffffffffff0000ffff"
             "0000ffff0f07f6ff546500ff000000ff000000ff0000ffff0000ffff000000ff000000ff273900ff"
             "517d00fff5ff00ff000000ff5d51ffff5c51ffff000000ffedff00ff426f00ff"sv},
    };
    for (const auto& v : vectors) {
        auto hash = thumbhash::encode(test_image(v.w, v.h, v.alpha), v.w, v.h);
        auto img = thumbhash::decode(hash, 8, 6);
        REQUIRE(img.width == 8);
        REQUIRE(img.height == 6);
        REQUIRE(img.rgba.size() == 8 * 6 * 4);
        INFO(v.w << "x" << v.h << (v.alpha ? " rgba" : " rgb"));
        CHECK(oxenc::to_hex(img.rgba) == v.expected);
    }
}
