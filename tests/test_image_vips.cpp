#include <vips/vips.h>

#include <catch2/catch_test_macros.hpp>
#include <optional>
#include <session/image/vips.hpp>
#include <string>
#include <vector>

namespace image = session::image;

namespace {

bool under_allowed_loader(GType type) {
    for (auto name : image::allowed_loaders)
        if (GType allowed = g_type_from_name(std::string{name}.c_str());
            allowed && g_type_is_a(type, allowed))
            return true;
    return false;
}

struct loader_audit {
    std::vector<std::string> open_but_not_allowed;
    std::vector<std::string> allowed_but_blocked;
    int blocked = 0;
};

void* audit_loader(VipsObjectClass* cls, void* a) {
    auto& audit = *static_cast<loader_audit*>(a);
    std::string name = G_OBJECT_CLASS_NAME(cls);
    bool blocked = VIPS_OPERATION_CLASS(cls)->flags & VIPS_OPERATION_BLOCKED;
    bool allowed = under_allowed_loader(G_OBJECT_CLASS_TYPE(cls));
    if (blocked)
        audit.blocked++;
    if (allowed && blocked)
        audit.allowed_but_blocked.push_back(name);
    else if (!allowed && !blocked)
        audit.open_but_not_allowed.push_back(name);
    return nullptr;
}

std::string joined(const std::vector<std::string>& names) {
    std::string out;
    for (auto& n : names)
        out += (out.empty() ? "" : ", ") + n;
    return out;
}

// Encodes a small image with whichever saver libvips has for `suffix`; nullopt if it has none.
std::optional<std::string> encode(const char* suffix) {
    VipsImage* img = nullptr;
    if (vips_black(&img, 4, 4, "bands", 3, nullptr))
        throw std::runtime_error{vips_error_buffer()};
    void* buf = nullptr;
    size_t len = 0;
    int rc = vips_image_write_to_buffer(img, suffix, &buf, &len, nullptr);
    g_object_unref(img);
    if (rc) {
        vips_error_clear();
        return std::nullopt;
    }
    std::string out{static_cast<const char*>(buf), len};
    g_free(buf);
    return out;
}

// The class name of the loader libvips selects for `data` by sniffing, exactly as when loading
// from a source.
std::optional<std::string> sniffed_loader(const std::string& data) {
    VipsSource* source = vips_source_new_from_memory(data.data(), data.size());
    const char* loader = vips_foreign_find_load_source(source);
    std::optional<std::string> result;
    if (loader)
        result = loader;
    g_object_unref(source);
    vips_error_clear();
    return result;
}

bool loads(const std::string& data) {
    VipsSource* source = vips_source_new_from_memory(data.data(), data.size());
    VipsImage* img = vips_image_new_from_source(source, "", nullptr);
    g_object_unref(source);
    if (!img) {
        vips_error_clear();
        return false;
    }
    g_object_unref(img);
    return true;
}

}  // namespace

TEST_CASE("libvips loader whitelist", "[image][vips]") {
    image::init();
    image::init();  // Repeat calls are no-ops

    for (auto name : image::allowed_loaders)
        if (!g_type_from_name(std::string{name}.c_str()))
            WARN("This libvips (" << vips_version_string() << ") has no " << name << " loader");

    loader_audit audit;
    vips_class_map_all(g_type_from_name("VipsForeignLoad"), audit_loader, &audit);
    INFO("libvips " << vips_version_string());
    INFO("loaders left open that are not whitelisted: " << joined(audit.open_but_not_allowed));
    CHECK(audit.open_but_not_allowed.empty());
    INFO("whitelisted loaders that are blocked: " << joined(audit.allowed_but_blocked));
    CHECK(audit.allowed_but_blocked.empty());
    // The matrix, csv, raw and vips loaders are built into every libvips, so there is always
    // something that has to be blocked; seeing none would mean the audit saw nothing at all.
    CHECK(audit.blocked > 0);
}

TEST_CASE("libvips loads only whitelisted formats", "[image][vips]") {
    image::init();

    SECTION("whitelisted formats are recognized") {
        for (auto [suffix, loader] :
             {std::pair{".jpg", "VipsForeignLoadJpegSource"},
              {".png", "VipsForeignLoadPngSource"},
              {".webp", "VipsForeignLoadWebpSource"},
              {".gif", "VipsForeignLoadNsgifSource"}}) {
            INFO(suffix);
            auto encoded = encode(suffix);
            REQUIRE(encoded);
            CHECK(sniffed_loader(*encoded) == loader);
            CHECK(loads(*encoded));
        }
    }

    SECTION("built-in libvips formats are refused") {
        // The matrix loader is compiled into every libvips, our static build included, and is not
        // flagged untrusted, so only the whitelist keeps it out.
        std::string matrix = "2 2\n0 0\n0 0\n";
        CHECK(sniffed_loader(matrix) == std::nullopt);
        CHECK_FALSE(loads(matrix));
    }

    SECTION("formats that only a system libvips might have are refused") {
        // These only prove anything against a libvips that has the loader; ours does not, and
        // there the refusal is trivial.
        std::string svg = R"(<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4"><rect )"
                          R"(width="4" height="4"/></svg>)";
        CHECK(sniffed_loader(svg) == std::nullopt);
        CHECK_FALSE(loads(svg));

        // TIFF matters in particular because libvips does not flag its loader untrusted.
        if (auto tiff = encode(".tif")) {
            CHECK(sniffed_loader(*tiff) == std::nullopt);
            CHECK_FALSE(loads(*tiff));
        }
    }
}
