#pragma once

#include <vips/vips.h>

#include <memory>
#include <string_view>

namespace session::image::detail {

struct gobject_unref {
    void operator()(void* p) const { g_object_unref(p); }
};
using image_ptr = std::unique_ptr<VipsImage, gobject_unref>;

// Throws std::runtime_error saying `what`, followed by libvips' error buffer, which it clears.
[[noreturn]] void throw_vips_error(std::string_view what);

}  // namespace session::image::detail
