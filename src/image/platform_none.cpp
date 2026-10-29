#include <stdexcept>

#include "platform.hpp"

namespace session::image::detail {

bool platform_decodes(Format) {
    return false;
}

image_ptr platform_decode(Source&, Format, uint32_t) {
    throw std::logic_error{"platform_decode: this platform has no image decoder of its own"};
}

}  // namespace session::image::detail
