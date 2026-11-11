#include "session/image/vips.hpp"

#include <libheif/heif.h>
#include <vips/vips.h>

#include <mutex>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <stdexcept>
#include <string>

#include "vips_internal.hpp"

namespace session::image {

using namespace oxen::log::literals;

static auto cat = oxen::log::Cat("image");

void detail::throw_vips_error(std::string_view what) {
    std::string err = vips_error_buffer();
    vips_error_clear();
    throw std::runtime_error{"{}: {}"_format(what, err)};
}

void init() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (VIPS_INIT("libsession")) {
            std::string err = vips_error_buffer();
            vips_error_clear();
            throw std::runtime_error{"libvips initialization failed: {}"_format(err)};
        }

        // Blocking a class blocks everything beneath it, so this blocks every loader, and each
        // unblock below then reopens one format's base class along with its file, buffer and source
        // subclasses.  Loaders registered from libvips modules are covered as well: vips_init()
        // loads modules, so they are already registered by this point.
        vips_operation_block_set("VipsForeignLoad", TRUE);
        for (auto loader : allowed_loaders) {
            std::string name{loader};
            // Not vips_type_find(): that only searches concrete classes, and these format base
            // classes are abstract.  This is the lookup vips_operation_block_set() itself uses.
            if (GType type = g_type_from_name(name.c_str());
                type && g_type_is_a(type, VIPS_TYPE_OPERATION))
                vips_operation_block_set(name.c_str(), FALSE);
            else
                oxen::log::warning(
                        cat,
                        "libvips {} has no {} loader; images in that format will not load",
                        vips_version_string(),
                        name);
        }

        // The operation cache memoises operations by their arguments, which helps only a program
        // repeating identical pipelines, and can keep decoded images alive after we are done.
        vips_cache_set_max(0);

        // probe() calls libheif itself, which must be initialised first; libvips does its own.
        heif_init(nullptr);
    });
}

}  // namespace session::image
