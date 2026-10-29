#include <fmt/core.h>
#include <session/types.h>

#include <session/types.hpp>

namespace session {
span_u8 span_u8_alloc_or_throw(size_t size) {
    span_u8 result = {};
    result.size = size;
    result.data = static_cast<unsigned char*>(malloc(size));
    // malloc(0) may return null, which is not running out of memory.
    if (!result.data && size > 0)
        throw std::runtime_error(
                fmt::format("Failed to allocate {} bytes for span, out of memory", size));
    return result;
}

span_u8 span_u8_copy_or_throw(const void* data, size_t size) {
    span_u8 result = span_u8_alloc_or_throw(size);
    // An empty source may be null, and memcpy's pointers must not be, even for 0 bytes.
    if (size > 0)
        std::memcpy(result.data, data, result.size);
    return result;
}
};  // namespace session
