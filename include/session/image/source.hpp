#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>

#include "session/attachments.hpp"

namespace session::image {

namespace detail {
    struct source_access;
}

/// API: image/Source
///
/// Where an image's encoded bytes come from.  Every image operation takes a `Source&` and works the
/// same whichever of the three kinds it is:
///
/// - in memory, e.g. a link-preview image just fetched;
/// - a plain file, e.g. one the user has just picked;
/// - a file encrypted in Session's `'S'` attachment format (as the client download cache is),
///   decrypted only as far as an operation actually reads, never into memory as a whole.
///
/// A source can be used more than once: probing it and then processing it reads it twice.  It is
/// not safe to use one Source from several threads at once.
class Source {
  public:
    /// An image in memory.  The bytes are not copied: they must outlive the Source, which is what
    /// `keep_alive` is for when the caller will not otherwise keep them -- anything owning the data
    /// can be put into a `shared_ptr`, and the Source holds it until destroyed.
    Source(std::span<const std::byte> data, std::shared_ptr<void> keep_alive = nullptr);

    /// An image in a plain file.
    ///
    /// Throws std::runtime_error if the file cannot be opened.
    explicit Source(const std::filesystem::path& file);

    /// An image in a file encrypted with attachment::encrypt or a fixed-key attachment::Encryptor.
    ///
    /// Throws std::runtime_error if the file cannot be opened, is not a valid encrypted
    /// attachment, or the key is wrong.  Operations reading beyond what this checks throw the
    /// decryption error they hit, rather than treating the file as "not an image".
    Source(const std::filesystem::path& file,
           std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE> key);

    Source(Source&&) noexcept;
    Source& operator=(Source&&) noexcept;
    ~Source();

    /// The size of the encoded image: for an encrypted file, its decrypted size.
    uint64_t size() const;

  private:
    struct impl;
    std::unique_ptr<impl> pimpl;
    friend struct detail::source_access;
};

}  // namespace session::image
