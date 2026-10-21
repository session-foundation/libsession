#pragma once

#include <cstdint>

#include "session/image/probe.hpp"
#include "vips_internal.hpp"

namespace session::image::detail {

// Whether `format` is decoded by the operating system in this build rather than by libvips: HEIC
// on Apple platforms, through ImageIO, since we ship no HEVC decoder.  Nothing anywhere else.
bool platform_decodes(Format format);

// Decodes `source`, an image of `format` for which platform_decodes() is true, into an 8-bit sRGB
// libvips image (with an alpha band only if the image has one), orientation applied and HDR
// tone-mapped to standard range.  If `max_side` is non-zero and the image is larger, it is decoded
// scaled down so that its longer side is `max_side` -- at that size, not decoded in full first
// where the platform can avoid it.  The shorter side is then the platform's rounding of it, which
// can be a pixel off exact proportion (ImageIO makes 2000x1500 at 500 into 500x376).
//
// Throws std::invalid_argument if the image is over max_frame_pixels, std::runtime_error if it
// cannot be decoded.
image_ptr platform_decode(Source& source, Format format, uint32_t max_side);

}  // namespace session::image::detail
