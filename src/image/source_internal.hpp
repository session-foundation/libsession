#pragma once

#include <vips/vips.h>

#include "session/image/source.hpp"

namespace session::image::detail {

struct source_access {
    static VipsSource* vips(Source& source);

    // libvips reports a failed read on an encrypted source as a generic read error, because the
    // callback cannot throw into it; the real exception is kept, and this rethrows (and clears)
    // it.  Call it whenever a libvips call on the source fails, before treating the failure as
    // being about the image.
    static void rethrow_error(Source& source);
};

}  // namespace session::image::detail
