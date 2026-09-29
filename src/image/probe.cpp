#include "session/image/probe.hpp"

#include <libheif/heif.h>
#include <libheif/heif_items.h>
#include <libheif/heif_tiling.h>
#include <vips/vips.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <string_view>
#include <utility>

#include "source_internal.hpp"

namespace session::image {

namespace {

    struct gobject_unref {
        void operator()(void* p) const { g_object_unref(p); }
    };

    // HEIF item types, spelled out because libheif only gained named constants for them in 1.23.5.
    constexpr uint32_t fourcc(const char (&code)[5]) {
        return uint32_t(uint8_t(code[0])) << 24 | uint32_t(uint8_t(code[1])) << 16 |
               uint32_t(uint8_t(code[2])) << 8 | uint32_t(uint8_t(code[3]));
    }
    constexpr uint32_t ITEM_HEVC = fourcc("hvc1"), ITEM_AV1 = fourcc("av01"),
                       ITEM_GRID = fourcc("grid");

    // libheif reading through the Source's libvips source, so that every kind of source -- the
    // encrypted one included -- is read the same way.
    struct heif_source_reader {
        VipsSource* source;
        int64_t length;
        int64_t pos = 0;

        static int64_t get_position(void* self) {
            return static_cast<heif_source_reader*>(self)->pos;
        }

        static int read(void* data, size_t size, void* self_) {
            auto& self = *static_cast<heif_source_reader*>(self_);
            auto* out = static_cast<char*>(data);
            while (size > 0) {
                gint64 n = vips_source_read(self.source, out, size);
                if (n <= 0)
                    return 1;
                out += n;
                size -= static_cast<size_t>(n);
                self.pos += n;
            }
            return 0;
        }

        static int seek(int64_t position, void* self_) {
            auto& self = *static_cast<heif_source_reader*>(self_);
            if (vips_source_seek(self.source, position, SEEK_SET) != position)
                return 1;
            self.pos = position;
            return 0;
        }

        static heif_reader_grow_status wait_for_file_size(int64_t target, void* self) {
            return target <= static_cast<heif_source_reader*>(self)->length
                         ? heif_reader_grow_status_size_reached
                         : heif_reader_grow_status_size_beyond_eof;
        }
    };

    // The item type (codec) of a HEIF file's primary image: hvc1, av01, jpeg, unci, ....  A grid
    // image -- how phones store large photos -- is a mosaic of tiles, which are what carry the
    // codec.  nullopt if libheif cannot make sense of the file.
    std::optional<uint32_t> heif_primary_codec(Source& src) {
        VipsSource* vsrc = detail::source_access::vips(src);
        if (vips_source_rewind(vsrc))
            return std::nullopt;
        heif_source_reader state{vsrc, vips_source_length(vsrc)};
        if (state.length < 0)
            return std::nullopt;
        heif_reader reader{};
        reader.reader_api_version = 1;
        reader.get_position = heif_source_reader::get_position;
        reader.read = heif_source_reader::read;
        reader.seek = heif_source_reader::seek;
        reader.wait_for_file_size = heif_source_reader::wait_for_file_size;

        std::unique_ptr<heif_context, decltype(&heif_context_free)> ctx{
                heif_context_alloc(), &heif_context_free};
        auto err = heif_context_read_from_reader(ctx.get(), &reader, &state, nullptr);
        vips_source_rewind(vsrc);
        if (err.code != heif_error_Ok)
            return std::nullopt;

        heif_image_handle* handle_raw = nullptr;
        if (heif_context_get_primary_image_handle(ctx.get(), &handle_raw).code != heif_error_Ok)
            return std::nullopt;
        std::unique_ptr<heif_image_handle, decltype(&heif_image_handle_release)> handle{
                handle_raw, &heif_image_handle_release};

        uint32_t type =
                heif_item_get_item_type(ctx.get(), heif_image_handle_get_item_id(handle.get()));
        if (type == ITEM_GRID) {
            heif_item_id tile;
            if (heif_image_handle_get_grid_image_tile_id(handle.get(), 0, 0, 0, &tile).code !=
                heif_error_Ok)
                return std::nullopt;
            type = heif_item_get_item_type(ctx.get(), tile);
        }
        return type;
    }

}  // namespace

std::optional<Info> probe(Source& source) {
    VipsSource* vsrc = detail::source_access::vips(source);

    // Only whitelisted loaders can be found: anything else sniffs as unknown.
    const char* loader = vips_foreign_find_load_source(vsrc);
    detail::source_access::rethrow_error(source);
    if (!loader) {
        vips_error_clear();
        return std::nullopt;
    }
    std::string_view name{loader};

    Info info{};
    bool heif = false;
    if (name == "VipsForeignLoadJpegSource")
        info.format = Format::jpeg;
    else if (name == "VipsForeignLoadPngSource")
        info.format = Format::png;
    else if (name == "VipsForeignLoadWebpSource")
        info.format = Format::webp;
    else if (name == "VipsForeignLoadNsgifSource")
        info.format = Format::gif;
    else if (name == "VipsForeignLoadHeifSource") {
        heif = true;
        // Not libvips' "heif-compression": that is guessed from the file's brand, and calls
        // anything that is not branded AVIF "hevc" -- JPEG or JPEG 2000 inside HEIF included,
        // which a system libheif's plugins may well decode but no other client would.
        auto codec = heif_primary_codec(source);
        detail::source_access::rethrow_error(source);
        if (codec == ITEM_HEVC)
            info.format = Format::heic;
        else if (codec == ITEM_AV1)
            info.format = Format::avif;
        else
            return std::nullopt;
    } else
        return std::nullopt;

    VipsImage* raw =
            vips_image_new_from_source(vsrc, "", "access", VIPS_ACCESS_SEQUENTIAL, nullptr);
    detail::source_access::rethrow_error(source);
    if (!raw) {
        vips_error_clear();
        return std::nullopt;
    }
    std::unique_ptr<VipsImage, gobject_unref> img{raw};

    info.width = static_cast<uint32_t>(img->Xsize);
    info.height = static_cast<uint32_t>(vips_image_get_page_height(img.get()));
    info.frames = heif ? 1 : static_cast<uint32_t>(vips_image_get_n_pages(img.get()));
    info.orientation = static_cast<uint8_t>(vips_image_get_orientation(img.get()));
    if (info.orientation >= 5)
        std::swap(info.width, info.height);
    info.has_alpha = vips_image_hasalpha(img.get());
    info.decodable =
            info.format != Format::heic || heif_have_decoder_for_format(heif_compression_HEVC);
    info.size = source.size();
    return info;
}

}  // namespace session::image
