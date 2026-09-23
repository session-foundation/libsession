#pragma once

#include <array>
#include <string_view>

namespace session::image {

/// The libvips loaders that libsession allows, by libvips class name.  Each name covers that
/// loader's file, buffer and source variants.
///
/// This is exactly the set of formats our static libvips build enables (see
/// cmake/session-deps/deps/vips.cmake): JPEG, PNG, WebP, GIF, and HEIF (which includes AVIF).  A
/// system libvips can carry many more loaders (SVG, PDF, TIFF, ImageMagick, ...), and libvips
/// picks a loader by sniffing the content rather than trusting a name or declared type, so any
/// loader present is reachable from any input.  `init()` therefore blocks every loader not listed
/// here, so that a client using a system libvips never decodes something other clients would
/// refuse.
///
/// libvips' own `untrusted` flag is not a substitute: the TIFF and matrix loaders, for instance,
/// are not flagged untrusted, and the matrix loader is built into every libvips.
inline constexpr std::array<std::string_view, 5> allowed_loaders{
        "VipsForeignLoadJpeg",
        // libspng in our static build; a system libvips built with libpng provides the same class.
        "VipsForeignLoadPng",
        "VipsForeignLoadWebp",
        // libvips' built-in libnsgif.
        "VipsForeignLoadNsgif",
        // HEIC and AVIF, via libheif.
        "VipsForeignLoadHeif",
};

/// API: image/init
///
/// Initializes libvips and restricts it to `allowed_loaders`.  Every libsession image function
/// calls this itself before touching libvips, so calling it explicitly is only needed to control
/// when the one-time cost happens (for example, at startup).  Safe to call repeatedly and from any
/// thread: only the first successful call does anything.
///
/// The loader restriction is global to the libvips instance.  If the application shares a libvips
/// with libsession (i.e. both use the same system library) then the application's own image
/// loading is restricted too.
///
/// A loader in `allowed_loaders` that this libvips does not have (e.g. a system libvips built
/// without libheif) is logged as a warning and otherwise ignored: images of that format simply fail
/// to load.
///
/// Throws std::runtime_error if libvips fails to initialize; a later call will try again.
void init();

}  // namespace session::image
