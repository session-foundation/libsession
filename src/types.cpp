#include <fmt/format.h>
#include <session/types.h>

#include <cstdlib>
#include <cstring>
#include <session/types.hpp>
#include <stdexcept>

namespace session {
span_u8 span_u8_alloc_or_throw(size_t size) {
    span_u8 result = {};
    result.size = size;
    result.data = static_cast<unsigned char*>(malloc(size));
    if (!result.data)
        throw std::runtime_error(
                fmt::format("Failed to allocate {} bytes for span, out of memory", size));
    return result;
}

span_u8 span_u8_copy_or_throw(const void* data, size_t size) {
    span_u8 result = span_u8_alloc_or_throw(size);
    std::memcpy(result.data, data, result.size);
    return result;
}
};  // namespace session
