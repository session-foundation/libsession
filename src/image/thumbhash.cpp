#include "session/image/thumbhash.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string>

#include "det_trig.hpp"

// Port of ThumbHash (https://github.com/evanw/thumbhash, MIT), with two deliberate departures from
// the reference implementation, both verified to leave the output bit-identical except where
// noted:
//
//  - The DCT basis is evaluated through session::image::detail (see det_trig.hpp), so that the
//    result does not depend on the platform's libm or on FMA contraction.  This *does* change the
//    hash relative to the reference, by at most 1 in an individual 4-bit AC coefficient, in
//    exchange for being identical everywhere.  Decoders remain fully interoperable; nothing
//    requires two encoders to agree.
//
//  - The basis tables are hoisted out of the innermost loops.  The reference rebuilds them inside
//    the (cx, cy) loop when encoding and inside the per-pixel loop when decoding, recomputing each
//    value many times over.  Accumulation order is untouched, so this is a pure strength
//    reduction: bit-identical, and roughly 3x faster in both directions.

namespace session::image::thumbhash {

namespace {

    using detail::cos_dct;

    // ECMAScript Math.round: round half toward +Infinity.  Not the same as floor(v + 0.5), which
    // rounds 0.49999999999999994 up to 1 because the addition itself rounds to 1.0.
    int iround(double v) {
        double f = std::floor(v);
        return int(v - f >= 0.5 ? f + 1 : f);
    }

    struct channel {
        double dc = 0;
        std::vector<double> ac;
        double scale = 0;
    };

    // Largest component count any channel uses: luminance goes up to 7x7, and max(3, lx) never
    // exceeds that.
    constexpr int max_components = 7;

    // Basis table indexed [c * n + i] for cos(pi/n * c * (i + 0.5)).  Built once per image and
    // shared by every channel.
    std::vector<double> basis(int n) {
        std::vector<double> t(size_t(max_components) * n);
        for (int c = 0; c < max_components; c++)
            for (int i = 0; i < n; i++)
                t[size_t(c) * n + i] = cos_dct(c, i, n);
        return t;
    }

    // DCT over the w*h channel, keeping the triangular set of (cx, cy) terms the format keeps:
    // cx * ny < nx * (ny - cy).
    channel encode_channel(
            const std::vector<double>& ch,
            int w,
            int h,
            int nx,
            int ny,
            const std::vector<double>& fxt,
            const std::vector<double>& fyt) {
        channel out;
        for (int cy = 0; cy < ny; cy++) {
            for (int cx = 0; cx * ny < nx * (ny - cy); cx++) {
                double f = 0;
                const double* fx = &fxt[size_t(cx) * w];
                const double* fyr = &fyt[size_t(cy) * h];
                for (int y = 0; y < h; y++) {
                    double fy = fyr[y];
                    for (int x = 0; x < w; x++)
                        f = std::fma(ch[size_t(x) + size_t(y) * w] * fx[size_t(x)], fy, f);
                }
                f /= double(w) * h;
                if (cx || cy) {
                    out.ac.push_back(f);
                    out.scale = std::max(out.scale, std::fabs(f));
                } else {
                    out.dc = f;
                }
            }
        }
        if (out.scale) {
            double inv = 0.5 / out.scale;
            for (auto& v : out.ac)
                v = std::fma(inv, v, 0.5);
        }
        return out;
    }

    uint8_t byte_at(std::span<const std::byte> h, size_t i) {
        return std::to_integer<uint8_t>(h[i]);
    }

    // The part of the header that determines the hash's layout: which channels are present and
    // how many coefficients each carries.  Everything after this point in the hash is a function
    // of these, which is what lets `expected_size` work without decoding.
    struct shape {
        bool has_alpha;
        int stored;  // the raw 3-bit count, before the decoder's max(3, ...) clamp
        int lx, ly;
        size_t ac_start;
    };

    shape read_shape(std::span<const std::byte> hash) {
        shape s{};
        uint32_t h16 = byte_at(hash, 3) | (uint32_t(byte_at(hash, 4)) << 8);
        s.has_alpha = (byte_at(hash, 2) & 0x80) != 0;
        s.stored = int(h16 & 7);
        bool landscape = (h16 >> 15) != 0;
        // The DCT needs at least three components per axis, so the decoder works with a clamped
        // count even where the encoder stored 1 or 2.  component_aspect_ratio deliberately reports
        // the unclamped value instead, which is what upstream does and what makes 7:1 reachable.
        s.lx = std::max(3, landscape ? (s.has_alpha ? 5 : 7) : s.stored);
        s.ly = std::max(3, landscape ? s.stored : (s.has_alpha ? 5 : 7));
        s.ac_start = s.has_alpha ? 6 : 5;
        return s;
    }

    // LPQA -> RGBA8.  Used both per-pixel by `decode` and once by `average_rgba` for the DC terms;
    // sharing it is what keeps the flat-colour placeholder from drifting away from the decoded
    // image it stands in for.
    std::array<std::byte, 4> lpqa_to_rgba8(double l, double p, double q, double a) {
        double b = std::fma(-(2.0 / 3.0), p, l);
        double r = (std::fma(3.0, l, -b) + q) / 2;
        double g = r - q;
        auto to8 = [](double v) {
            return std::byte(uint8_t(std::max(0.0, 255 * std::min(1.0, v))));
        };
        return {to8(r), to8(g), to8(b), to8(a)};
    }

    // Number of AC coefficients a channel contributes: the triangular set the format keeps, minus
    // the DC term.  Must stay in step with the loop in `decode`'s decode_channel.
    size_t ac_count(int nx, int ny) {
        size_t n = 0;
        for (int cy = 0; cy < ny; cy++)
            for (int cx = cy ? 0 : 1; cx * ny < nx * (ny - cy); cx++)
                n++;
        return n;
    }

    // Everything a decoder needs from the fixed-size part of a hash.
    struct header {
        double l_dc, p_dc, q_dc, a_dc;
        double l_scale, p_scale, q_scale, a_scale;
        bool has_alpha;
        int lx, ly;
        size_t ac_start;
    };

    header read_header(std::span<const std::byte> hash) {
        if (hash.size() < 5)
            throw std::invalid_argument{"thumbhash: too short"};
        auto s = read_shape(hash);
        header hd{};
        uint32_t h24 = byte_at(hash, 0) | (uint32_t(byte_at(hash, 1)) << 8) |
                       (uint32_t(byte_at(hash, 2)) << 16);
        uint32_t h16 = byte_at(hash, 3) | (uint32_t(byte_at(hash, 4)) << 8);
        hd.l_dc = (h24 & 63) / 63.0;
        hd.p_dc = ((h24 >> 6) & 63) / 31.5 - 1;
        hd.q_dc = ((h24 >> 12) & 63) / 31.5 - 1;
        hd.l_scale = ((h24 >> 18) & 31) / 31.0;
        hd.p_scale = ((h16 >> 3) & 63) / 63.0;
        hd.q_scale = ((h16 >> 9) & 63) / 63.0;
        hd.has_alpha = s.has_alpha;
        hd.lx = s.lx;
        hd.ly = s.ly;
        hd.ac_start = s.ac_start;
        if (hd.has_alpha && hash.size() < 6)
            throw std::invalid_argument{"thumbhash: truncated before alpha DC"};
        hd.a_dc = hd.has_alpha ? (byte_at(hash, 5) & 15) / 15.0 : 1.0;
        hd.a_scale = hd.has_alpha ? (byte_at(hash, 5) >> 4) / 15.0 : 0.0;
        return hd;
    }

}  // namespace

std::optional<size_t> expected_size(std::span<const std::byte> hash) {
    if (hash.size() < 5)
        return std::nullopt;
    auto s = read_shape(hash);
    if (s.has_alpha && hash.size() < 6)
        return std::nullopt;
    // No conforming encoder emits a component count of 0 -- both this one and upstream clamp to
    // max(1, ...).  The decoder's max(3, ...) would silently accept it, but component_aspect_ratio
    // reads the field unclamped and rejects it, so treating it as well-formed here would let a
    // value through the trust boundary that the rest of the API refuses.
    if (s.stored == 0)
        return std::nullopt;
    size_t nibbles = ac_count(s.lx, s.ly) + 2 * ac_count(3, 3) + (s.has_alpha ? ac_count(5, 5) : 0);
    return s.ac_start + (nibbles + 1) / 2;
}

bool valid(std::span<const std::byte> hash) {
    auto n = expected_size(hash);
    return n && *n == hash.size();
}

std::vector<std::byte> encode(std::span<const std::byte> rgba, uint32_t width, uint32_t height) {
    if (width < 1 || height < 1 || width > max_input_dimension || height > max_input_dimension)
        throw std::invalid_argument{
                "thumbhash: dimensions must be between 1 and " +
                std::to_string(max_input_dimension)};
    if (rgba.size() != size_t(width) * height * 4)
        throw std::invalid_argument{"thumbhash: rgba buffer size does not match dimensions"};

    int w = int(width), h = int(height);
    auto px = [&](size_t i) { return double(std::to_integer<uint8_t>(rgba[i])); };

    double avg_r = 0, avg_g = 0, avg_b = 0, avg_a = 0;
    for (size_t i = 0, j = 0; i < size_t(w) * h; i++, j += 4) {
        double alpha = px(j + 3) / 255.0;
        double s = alpha / 255;
        avg_r = std::fma(s, px(j), avg_r);
        avg_g = std::fma(s, px(j + 1), avg_g);
        avg_b = std::fma(s, px(j + 2), avg_b);
        avg_a += alpha;
    }
    if (avg_a) {
        avg_r /= avg_a;
        avg_g /= avg_a;
        avg_b /= avg_a;
    }

    bool has_alpha = avg_a < double(w) * h;
    int l_limit = has_alpha ? 5 : 7;  // fewer luminance components when alpha needs the space
    int lx = std::max(1, iround(double(l_limit) * w / std::max(w, h)));
    int ly = std::max(1, iround(double(l_limit) * h / std::max(w, h)));

    // Convert to LPQA, compositing over the average colour so that transparent regions do not drag
    // the DCT toward black.
    size_t n = size_t(w) * h;
    std::vector<double> l(n), p(n), q(n), a(n);
    for (size_t i = 0, j = 0; i < n; i++, j += 4) {
        double alpha = px(j + 3) / 255.0;
        double s = alpha / 255, inv = 1 - alpha;
        double r = std::fma(avg_r, inv, s * px(j));
        double g = std::fma(avg_g, inv, s * px(j + 1));
        double b = std::fma(avg_b, inv, s * px(j + 2));
        l[i] = (r + g + b) / 3;
        p[i] = (r + g) / 2 - b;
        q[i] = r - g;
        a[i] = alpha;
    }

    auto fxt = basis(w), fyt = basis(h);
    auto lc = encode_channel(l, w, h, std::max(3, lx), std::max(3, ly), fxt, fyt);
    auto pc = encode_channel(p, w, h, 3, 3, fxt, fyt);
    auto qc = encode_channel(q, w, h, 3, 3, fxt, fyt);
    channel ac_a;
    if (has_alpha)
        ac_a = encode_channel(a, w, h, 5, 5, fxt, fyt);

    bool landscape = w > h;
    uint32_t header24 = uint32_t(iround(63 * lc.dc)) |
                        (uint32_t(iround(std::fma(31.5, pc.dc, 31.5))) << 6) |
                        (uint32_t(iround(std::fma(31.5, qc.dc, 31.5))) << 12) |
                        (uint32_t(iround(31 * lc.scale)) << 18) | (uint32_t(has_alpha) << 23);
    uint32_t header16 = uint32_t(landscape ? ly : lx) | (uint32_t(iround(63 * pc.scale)) << 3) |
                        (uint32_t(iround(63 * qc.scale)) << 9) | (uint32_t(landscape) << 15);

    std::vector<std::byte> hash;
    hash.reserve(max_hash_size);
    auto push = [&hash](int v) { hash.push_back(std::byte(static_cast<uint8_t>(v))); };
    push(header24 & 255);
    push((header24 >> 8) & 255);
    push((header24 >> 16) & 255);
    push(header16 & 255);
    push((header16 >> 8) & 255);
    if (has_alpha)
        push(iround(15 * ac_a.dc) | (iround(15 * ac_a.scale) << 4));

    size_t ac_start = hash.size(), ac_index = 0;
    auto put = [&](const std::vector<double>& v) {
        for (double f : v) {
            size_t byte = ac_start + (ac_index >> 1);
            if (byte >= hash.size())
                hash.resize(byte + 1, std::byte{0});
            // Two 4-bit coefficients per byte, low nibble first.
            hash[byte] |= std::byte(static_cast<uint8_t>(iround(15 * f) << ((ac_index & 1) << 2)));
            ac_index++;
        }
    };
    put(lc.ac);
    put(pc.ac);
    put(qc.ac);
    if (has_alpha)
        put(ac_a.ac);
    return hash;
}

double component_aspect_ratio(std::span<const std::byte> hash) {
    if (hash.size() < 5)
        throw std::invalid_argument{"thumbhash: too short"};
    bool has_alpha = byte_at(hash, 2) & 0x80;
    bool landscape = byte_at(hash, 4) & 0x80;
    int lx = landscape ? (has_alpha ? 5 : 7) : (byte_at(hash, 3) & 7);
    int ly = landscape ? (byte_at(hash, 3) & 7) : (has_alpha ? 5 : 7);
    if (ly == 0)
        throw std::invalid_argument{"thumbhash: invalid component count"};
    return double(lx) / ly;
}

std::array<std::byte, 4> average_rgba(std::span<const std::byte> hash) {
    auto hd = read_header(hash);
    return lpqa_to_rgba8(hd.l_dc, hd.p_dc, hd.q_dc, hd.a_dc);
}

image decode(std::span<const std::byte> hash, uint32_t width, uint32_t height) {
    if (width < 1 || height < 1)
        throw std::invalid_argument{"thumbhash: output dimensions must be non-zero"};
    // No policy cap on the size -- a big decode is merely slow -- but the arithmetic below has to
    // survive one.  Both the byte count and the pixel index must fit in size_t, which they do not
    // on a 32-bit target for anything over ~1G pixels, and `int` counters would overflow at 2^29
    // pixels on any target.
    uint64_t bytes = uint64_t(width) * height * 4;
    if (bytes > std::numeric_limits<size_t>::max() ||
        uint64_t(std::max(width, height)) > uint64_t(std::numeric_limits<int32_t>::max()))
        throw std::invalid_argument{"thumbhash: output dimensions too large"};
    auto hd = read_header(hash);
    int w = int(width), h = int(height);

    size_t ac_index = 0;
    auto decode_channel = [&](int nx, int ny, double scale) {
        std::vector<double> ac;
        for (int cy = 0; cy < ny; cy++)
            for (int cx = cy ? 0 : 1; cx * ny < nx * (ny - cy); cx++) {
                size_t byte = hd.ac_start + (ac_index >> 1);
                if (byte >= hash.size())
                    throw std::invalid_argument{"thumbhash: truncated in AC terms"};
                int nib = (byte_at(hash, byte) >> ((ac_index & 1) << 2)) & 15;
                ac_index++;
                ac.push_back((nib / 7.5 - 1) * scale);
            }
        return ac;
    };
    // The format boosts chroma by 1.25x on decode to offset quantisation loss.
    auto l_ac = decode_channel(hd.lx, hd.ly, hd.l_scale);
    auto p_ac = decode_channel(3, 3, hd.p_scale * 1.25);
    auto q_ac = decode_channel(3, 3, hd.q_scale * 1.25);
    std::vector<double> a_ac;
    if (hd.has_alpha)
        a_ac = decode_channel(5, 5, hd.a_scale);

    image out{width, height, std::vector<std::byte>(size_t(bytes))};

    // The basis separates: fx depends only on (cx, x) and fy only on (cy, y).
    int nx = std::max(hd.lx, hd.has_alpha ? 5 : 3) + 1;
    int ny = std::max(hd.ly, hd.has_alpha ? 5 : 3) + 1;
    std::vector<double> fxt(size_t(w) * nx), fyt(size_t(h) * ny);
    for (int x = 0; x < w; x++)
        for (int cx = 0; cx < nx; cx++)
            fxt[size_t(x) * nx + cx] = cos_dct(cx, x, w);
    for (int y = 0; y < h; y++)
        for (int cy = 0; cy < ny; cy++)
            fyt[size_t(y) * ny + cy] = cos_dct(cy, y, h);

    // `i` is size_t, not int: at 2^29 output pixels a 32-bit counter wraps and the stores below
    // land outside the buffer.
    for (int y = 0; y < h; y++) {
        const double* fy = &fyt[size_t(y) * ny];
        size_t i = size_t(y) * w * 4;
        for (int x = 0; x < w; x++, i += 4) {
            double l = hd.l_dc, p = hd.p_dc, q = hd.q_dc, a = hd.a_dc;
            const double* fx = &fxt[size_t(x) * nx];

            for (int cy = 0, j = 0; cy < hd.ly; cy++) {
                double fy2 = fy[size_t(cy)] * 2;
                for (int cx = cy ? 0 : 1; cx * hd.ly < hd.lx * (hd.ly - cy); cx++, j++)
                    l = std::fma(l_ac[size_t(j)] * fx[size_t(cx)], fy2, l);
            }
            for (int cy = 0, j = 0; cy < 3; cy++) {
                double fy2 = fy[size_t(cy)] * 2;
                for (int cx = cy ? 0 : 1; cx < 3 - cy; cx++, j++) {
                    double f = fx[size_t(cx)] * fy2;
                    p = std::fma(p_ac[size_t(j)], f, p);
                    q = std::fma(q_ac[size_t(j)], f, q);
                }
            }
            if (hd.has_alpha)
                for (int cy = 0, j = 0; cy < 5; cy++) {
                    double fy2 = fy[size_t(cy)] * 2;
                    for (int cx = cy ? 0 : 1; cx < 5 - cy; cx++, j++)
                        a = std::fma(a_ac[size_t(j)] * fx[size_t(cx)], fy2, a);
                }

            auto rgba = lpqa_to_rgba8(l, p, q, a);
            out.rgba[i] = rgba[0];
            out.rgba[i + 1] = rgba[1];
            out.rgba[i + 2] = rgba[2];
            out.rgba[i + 3] = rgba[3];
        }
    }
    return out;
}

image decode_unsized(std::span<const std::byte> hash, uint32_t size) {
    if (size < 1)
        throw std::invalid_argument{"thumbhash: output size must be non-zero"};
    double ratio = component_aspect_ratio(hash);
    int w = iround(ratio > 1 ? size : size * ratio);
    int h = iround(ratio > 1 ? size / ratio : size);
    return decode(hash, uint32_t(std::max(1, w)), uint32_t(std::max(1, h)));
}

}  // namespace session::image::thumbhash
