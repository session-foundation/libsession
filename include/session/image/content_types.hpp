#pragma once

#include <algorithm>
#include <array>
#include <string_view>

namespace session::image {

/// The attachment content types Session treats as images: what a message may be shown as a gallery
/// of, what counts as an image in a conversation's preview, and what the `image_attachments`
/// auto-download mode fetches.  These are the formats the libvips loader whitelist accepts
/// (`allowed_loaders` in vips.hpp), and the two lists are to be kept in step.
///
/// HEIC/HEIF is deliberately absent even though some platforms can decode it: Session clients
/// convert HEIC to JPEG before sending, so one that arrives anyway is treated as a file.
///
/// `image/jpg` and `image/pjpeg` are not registered types, but are what some senders label JPEGs.
inline constexpr std::array<std::string_view, 7> displayable_image_types{
        "image/jpeg",
        "image/jpg",
        "image/pjpeg",
        "image/png",
        "image/webp",
        "image/gif",
        "image/avif",
};

/// API: image/is_displayable_image
///
/// Whether `content_type` is one of `displayable_image_types`, ignoring ASCII case: MIME types are
/// case-insensitive.  A content type is a sender's claim about a file, so this decides how an
/// attachment is presented, not whether its bytes are safe to decode; decoding enforces the loader
/// whitelist on the actual content.
constexpr bool is_displayable_image(std::string_view content_type) {
    auto lower = [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
    };
    return std::ranges::any_of(displayable_image_types, [&](std::string_view type) {
        return std::ranges::equal(content_type, type, {}, lower);
    });
}

}  // namespace session::image
