#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>

#include <algorithm>
#include <memory>
#include <oxen/log/format.hpp>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "platform.hpp"
#include "source_internal.hpp"

namespace session::image::detail {

using namespace oxen::log::literals;

namespace {

    struct cf_release {
        void operator()(const void* p) const {
            if (p)
                CFRelease(p);
        }
    };
    template <typename Ref>
    using cf_ptr = std::unique_ptr<std::remove_pointer_t<Ref>, cf_release>;

    int cf_int(CFDictionaryRef dict, CFStringRef key) {
        int value = 0;
        if (auto num = static_cast<CFNumberRef>(CFDictionaryGetValue(dict, key)))
            CFNumberGetValue(num, kCFNumberIntType, &value);
        return value;
    }

}  // namespace

bool platform_decodes(Format format) {
    return format == Format::heic;
}

image_ptr platform_decode(Source& source, Format format, uint32_t max_side) {
    if (!platform_decodes(format))
        throw std::logic_error{"platform_decode: not a format ImageIO is used for"};

    // ImageIO reads a HEIC whole whatever it is given to read from, so it may as well be memory.
    auto bytes = source_access::read_all(source);
    cf_ptr<CFDataRef> data{CFDataCreateWithBytesNoCopy(
            nullptr, reinterpret_cast<const UInt8*>(bytes.data()), bytes.size(), kCFAllocatorNull)};
    cf_ptr<CGImageSourceRef> src{CGImageSourceCreateWithData(data.get(), nullptr)};
    if (!src)
        throw std::runtime_error{"platform_decode: ImageIO cannot read this image"};

    size_t index = CGImageSourceGetPrimaryImageIndex(src.get());
    cf_ptr<CFDictionaryRef> props{CGImageSourceCopyPropertiesAtIndex(src.get(), index, nullptr)};
    if (!props)
        throw std::runtime_error{"platform_decode: ImageIO cannot read this image's header"};
    int width = cf_int(props.get(), kCGImagePropertyPixelWidth);
    int height = cf_int(props.get(), kCGImagePropertyPixelHeight);
    if (width <= 0 || height <= 0)
        throw std::runtime_error{"platform_decode: ImageIO reports no image size"};
    if (uint64_t(width) * uint64_t(height) > max_frame_pixels)
        throw std::invalid_argument{"platform_decode: {}x{} is over the {} pixel limit"_format(
                width, height, max_frame_pixels)};

    // The thumbnail call rather than CGImageSourceCreateImageAtIndex because it is the one that
    // can decode directly at a reduced size and bake in the orientation; asked for the image's own
    // longest side, it is simply a full-size decode.
    int longest = std::max(width, height);
    int target = max_side > 0 && max_side < uint32_t(longest) ? int(max_side) : longest;
    cf_ptr<CFNumberRef> target_num{CFNumberCreate(nullptr, kCFNumberIntType, &target)};
    const void* keys[] = {
            kCGImageSourceCreateThumbnailFromImageAlways,
            kCGImageSourceCreateThumbnailWithTransform,
            kCGImageSourceThumbnailMaxPixelSize,
            kCGImageSourceShouldCacheImmediately};
    const void* values[] = {kCFBooleanTrue, kCFBooleanTrue, target_num.get(), kCFBooleanTrue};
    cf_ptr<CFDictionaryRef> options{CFDictionaryCreate(
            nullptr,
            keys,
            values,
            std::size(keys),
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks)};
    cf_ptr<CGImageRef> decoded{
            CGImageSourceCreateThumbnailAtIndex(src.get(), index, options.get())};
    if (!decoded)
        throw std::runtime_error{"platform_decode: ImageIO failed to decode the image"};

    size_t w = CGImageGetWidth(decoded.get()), h = CGImageGetHeight(decoded.get());
    // Not the decoded image's own alpha info: the thumbnail call hands back premultiplied RGBA
    // even for an opaque image.
    auto has_alpha =
            static_cast<CFBooleanRef>(CFDictionaryGetValue(props.get(), kCGImagePropertyHasAlpha));
    bool alpha = has_alpha && CFBooleanGetValue(has_alpha);

    // Drawing into an 8-bit sRGB context is what converts wide-gamut colour and tone-maps HDR.
    cf_ptr<CGColorSpaceRef> srgb{CGColorSpaceCreateWithName(kCGColorSpaceSRGB)};
    std::vector<uint8_t> pixels(w * h * 4);
    cf_ptr<CGContextRef> ctx{CGBitmapContextCreate(
            pixels.data(),
            w,
            h,
            8,
            w * 4,
            srgb.get(),
            CGBitmapInfo(alpha ? kCGImageAlphaPremultipliedLast : kCGImageAlphaNoneSkipLast) |
                    kCGImageByteOrder32Big)};
    if (!ctx)
        throw std::runtime_error{"platform_decode: cannot create a {}x{} bitmap"_format(w, h)};
    CGContextDrawImage(ctx.get(), CGRectMake(0, 0, w, h), decoded.get());

    VipsImage* raw = vips_image_new_from_memory_copy(
            pixels.data(), pixels.size(), int(w), int(h), 4, VIPS_FORMAT_UCHAR);
    if (!raw)
        throw_vips_error("platform_decode: cannot wrap the decoded pixels");
    image_ptr img{raw};
    VipsImage* next;
    if (alpha) {
        // CoreGraphics draws only premultiplied alpha, which nothing downstream expects.
        if (vips_unpremultiply(img.get(), &next, nullptr))
            throw_vips_error("platform_decode: unpremultiply failed");
        img.reset(next);
        if (vips_cast_uchar(img.get(), &next, nullptr))
            throw_vips_error("platform_decode: conversion to 8 bits failed");
        img.reset(next);
    } else {
        if (vips_extract_band(img.get(), &next, 0, "n", 3, nullptr))
            throw_vips_error("platform_decode: dropping the padding band failed");
        img.reset(next);
    }
    if (vips_copy(img.get(), &next, "interpretation", VIPS_INTERPRETATION_sRGB, nullptr))
        throw_vips_error("platform_decode: setting the colour space failed");
    img.reset(next);
    return img;
}

}  // namespace session::image::detail
