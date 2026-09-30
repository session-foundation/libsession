#include "session/image/source.hpp"

#include <cstdio>
#include <exception>
#include <mutex>
#include <optional>
#include <oxen/log/format.hpp>
#include <stdexcept>
#include <string>
#include <utility>

#include "session/image/vips.hpp"
#include "source_internal.hpp"
#include "vips_internal.hpp"

namespace session::image {

using namespace oxen::log::literals;

struct Source::impl {
    VipsSource* source = nullptr;
    std::shared_ptr<void> keep_alive;
    uint64_t size = 0;

    std::optional<attachment::SeekableDecryptor> decryptor;
    // libvips can read a source from its worker threads, and the decryptor is not thread-safe.
    std::mutex decrypt_mutex;
    std::exception_ptr error;

    ~impl() {
        if (source)
            g_object_unref(source);
    }

    // The encrypted source's "read" and "seek" signal handlers.  These are C callbacks, so an
    // exception is stored for rethrow_error() instead of escaping into libvips.
    static gint64 decrypt_read(VipsSourceCustom*, void* buffer, gint64 length, void* user) {
        auto& self = *static_cast<impl*>(user);
        try {
            std::lock_guard lock{self.decrypt_mutex};
            return static_cast<gint64>(self.decryptor->read(
                    {static_cast<std::byte*>(buffer), static_cast<size_t>(length)}));
        } catch (...) {
            self.error = std::current_exception();
            return -1;
        }
    }

    static gint64 decrypt_seek(VipsSourceCustom*, gint64 offset, int whence, void* user) {
        auto& self = *static_cast<impl*>(user);
        std::lock_guard lock{self.decrypt_mutex};
        auto& dec = *self.decryptor;
        gint64 base = whence == SEEK_SET ? 0
                    : whence == SEEK_CUR ? static_cast<gint64>(dec.tell())
                    : whence == SEEK_END ? static_cast<gint64>(dec.size())
                                         : -1;
        if (base < 0 || base + offset < 0)
            return -1;
        dec.seek(static_cast<uint64_t>(base + offset));
        return base + offset;
    }
};

using detail::throw_vips_error;

Source::Source(std::span<const std::byte> data, std::shared_ptr<void> keep_alive) :
        pimpl{std::make_unique<impl>()} {
    init();
    pimpl->source = vips_source_new_from_memory(data.data(), data.size());
    if (!pimpl->source)
        throw_vips_error("image source: cannot read memory");
    pimpl->keep_alive = std::move(keep_alive);
    pimpl->size = data.size();
}

Source::Source(const std::filesystem::path& file) : pimpl{std::make_unique<impl>()} {
    init();
    auto name = file.u8string();
    pimpl->source = vips_source_new_from_file(reinterpret_cast<const char*>(name.c_str()));
    if (!pimpl->source)
        throw_vips_error("image source: cannot open {}"_format(file.string()));
    pimpl->size = std::filesystem::file_size(file);
}

Source::Source(
        const std::filesystem::path& file,
        std::span<const std::byte, attachment::ENCRYPT_KEY_SIZE> key) :
        pimpl{std::make_unique<impl>()} {
    init();
    pimpl->decryptor.emplace(file, key);
    pimpl->size = pimpl->decryptor->size();
    VipsSourceCustom* custom = vips_source_custom_new();
    pimpl->source = VIPS_SOURCE(custom);
    g_signal_connect(custom, "read", G_CALLBACK(impl::decrypt_read), pimpl.get());
    g_signal_connect(custom, "seek", G_CALLBACK(impl::decrypt_seek), pimpl.get());
}

Source::Source(Source&&) noexcept = default;
Source& Source::operator=(Source&&) noexcept = default;
Source::~Source() = default;

uint64_t Source::size() const {
    return pimpl->size;
}

namespace detail {

    VipsSource* source_access::vips(Source& source) {
        return source.pimpl->source;
    }

    void source_access::rethrow_error(Source& source) {
        if (auto err = std::exchange(source.pimpl->error, nullptr)) {
            vips_error_clear();
            std::rethrow_exception(err);
        }
    }

}  // namespace detail

}  // namespace session::image
