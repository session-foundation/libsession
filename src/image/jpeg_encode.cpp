#include "jpeg_encode.hpp"

#include <algorithm>
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <oxen/log/format.hpp>
#include <stdexcept>
#include <string>

#ifdef SESSION_ENABLE_JPEGLI
#include "lib/jpegli/encode.h"
#endif

namespace session::image::detail {

using namespace oxen::log::literals;

namespace {

    struct gobject_unref {
        void operator()(void* p) const { g_object_unref(p); }
    };
    using image_ptr = std::unique_ptr<VipsImage, gobject_unref>;

    [[noreturn]] void throw_vips_error(std::string_view what) {
        std::string err = vips_error_buffer();
        vips_error_clear();
        throw std::runtime_error{"encode_jpeg: {}: {}"_format(what, err)};
    }

    // What a JPEG can hold: 8-bit sRGB, or 8-bit greyscale for a single band.
    image_ptr to_jpeg_colourspace(VipsImage* in) {
        if (vips_image_hasalpha(in))
            throw std::invalid_argument{"encode_jpeg: JPEG cannot store an alpha channel"};

        // An image's interpretation can say nothing about its colour (a generated one is often just
        // "multiband"), so convert from what its bands and format suggest rather than refuse it.
        VipsImage* out;
        if (vips_colourspace(
                    in,
                    &out,
                    in->Bands == 1 ? VIPS_INTERPRETATION_B_W : VIPS_INTERPRETATION_sRGB,
                    "source_space",
                    vips_image_guess_interpretation(in),
                    nullptr))
            throw_vips_error("colour conversion failed");
        image_ptr img{out};

        if (img->BandFmt != VIPS_FORMAT_UCHAR) {
            if (vips_cast_uchar(img.get(), &out, nullptr))
                throw_vips_error("conversion to 8 bits failed");
            img.reset(out);
        }
        return img;
    }

#ifdef SESSION_ENABLE_JPEGLI

    constexpr int STRIP_ROWS = 64;

    struct jpegli_job {
        jpeg_compress_struct cinfo;
        jpeg_error_mgr err;
        std::jmp_buf jump;
        char error[JMSG_STR_PARM_MAX];
        unsigned char* out;
        unsigned long out_size;
    };

    [[noreturn]] void on_jpegli_error(j_common_ptr cinfo) {
        auto* job = reinterpret_cast<jpegli_job*>(cinfo);
        // jpegli formats its messages into msg_parm.s rather than using libjpeg's message codes.
        std::memcpy(job->error, cinfo->err->msg_parm.s, sizeof(job->error));
        job->error[sizeof(job->error) - 1] = '\0';
        std::longjmp(job->jump, 1);
    }

    // Every jpegli call is in here, because a jpegli error longjmps back to the setjmp below:
    // nothing in this function may need destroying, so the caller cleans up and throws.  Returns
    // false on failure, with the reason in job.error.
    bool run_jpegli(jpegli_job& job, VipsRegion* region, int quality, Subsampling subsampling) {
        VipsImage* img = region->im;

        job.cinfo.err = jpegli_std_error(&job.err);
        job.err.error_exit = on_jpegli_error;
        if (setjmp(job.jump))
            return false;

        jpegli_create_compress(&job.cinfo);
        jpegli_mem_dest(&job.cinfo, &job.out, &job.out_size);
        job.cinfo.image_width = img->Xsize;
        job.cinfo.image_height = img->Ysize;
        job.cinfo.input_components = img->Bands;
        job.cinfo.in_color_space = img->Bands == 1 ? JCS_GRAYSCALE : JCS_RGB;
        jpegli_set_defaults(&job.cinfo);
        // The quality mapping cjpegli uses; baseline-compatible (8-bit) quantisation tables.
        jpegli_set_distance(&job.cinfo, jpegli_quality_to_distance(quality), TRUE);
        jpegli_enable_adaptive_quantization(&job.cinfo, TRUE);
        jpegli_set_progressive_level(&job.cinfo, 2);
        if (img->Bands == 3) {
            int luma = subsampling == Subsampling::yuv420 ? 2 : 1;
            job.cinfo.comp_info[0].h_samp_factor = job.cinfo.comp_info[0].v_samp_factor = luma;
            for (int c = 1; c < 3; c++)
                job.cinfo.comp_info[c].h_samp_factor = job.cinfo.comp_info[c].v_samp_factor = 1;
        }
        jpegli_start_compress(&job.cinfo, TRUE);

        JSAMPROW rows[STRIP_ROWS];
        for (int top = 0; top < img->Ysize; top += STRIP_ROWS) {
            VipsRect strip{0, top, img->Xsize, std::min(STRIP_ROWS, img->Ysize - top)};
            if (vips_region_prepare(region, &strip)) {
                std::snprintf(job.error, sizeof(job.error), "%s", vips_error_buffer());
                vips_error_clear();
                return false;
            }
            for (int i = 0; i < strip.height; i++)
                rows[i] = VIPS_REGION_ADDR(region, 0, top + i);
            for (int written = 0; written < strip.height;)
                written +=
                        jpegli_write_scanlines(&job.cinfo, rows + written, strip.height - written);
        }
        jpegli_finish_compress(&job.cinfo);
        return true;
    }

    std::vector<std::byte> encode(VipsImage* img, int quality, Subsampling subsampling) {
        std::unique_ptr<VipsRegion, gobject_unref> region{vips_region_new(img)};
        jpegli_job job{};
        bool ok = run_jpegli(job, region.get(), quality, subsampling);
        jpegli_destroy_compress(&job.cinfo);
        std::unique_ptr<unsigned char, decltype(&std::free)> out{job.out, &std::free};
        if (!ok)
            throw std::runtime_error{"encode_jpeg: jpegli failed: {}"_format(job.error)};
        auto* data = reinterpret_cast<const std::byte*>(out.get());
        return {data, data + job.out_size};
    }

#else

    std::vector<std::byte> encode(VipsImage* img, int quality, Subsampling subsampling) {
        auto subsample = subsampling == Subsampling::yuv420 ? VIPS_FOREIGN_SUBSAMPLE_ON
                                                            : VIPS_FOREIGN_SUBSAMPLE_OFF;
        void* buf = nullptr;
        size_t len = 0;
        // `keep` replaced `strip` in 8.15; system libvips is accepted back to 8.13, whose headers
        // lack VIPS_FOREIGN_KEEP_NONE, hence the literal 0 (which is its value).
        bool have_keep = vips_version(0) > 8 || (vips_version(0) == 8 && vips_version(1) >= 15);
        int rc = have_keep ? vips_jpegsave_buffer(
                                     img,
                                     &buf,
                                     &len,
                                     "Q",
                                     quality,
                                     "optimize_coding",
                                     TRUE,
                                     "interlace",
                                     TRUE,
                                     "subsample_mode",
                                     subsample,
                                     "keep",
                                     0,
                                     nullptr)
                           : vips_jpegsave_buffer(
                                     img,
                                     &buf,
                                     &len,
                                     "Q",
                                     quality,
                                     "optimize_coding",
                                     TRUE,
                                     "interlace",
                                     TRUE,
                                     "subsample_mode",
                                     subsample,
                                     "strip",
                                     TRUE,
                                     nullptr);
        if (rc)
            throw_vips_error("libvips JPEG encoding failed");
        std::unique_ptr<void, decltype(&g_free)> owned{buf, &g_free};
        auto* data = static_cast<const std::byte*>(buf);
        return {data, data + len};
    }

#endif

}  // namespace

std::vector<std::byte> encode_jpeg(VipsImage* image, int quality, Subsampling subsampling) {
    if (quality < 1 || quality > 100)
        throw std::invalid_argument{"encode_jpeg: quality {} is not in [1, 100]"_format(quality)};
    auto img = to_jpeg_colourspace(image);
    return encode(img.get(), quality, subsampling);
}

std::string_view jpeg_encoder_name() {
#ifdef SESSION_ENABLE_JPEGLI
    return "jpegli";
#else
    return "libjpeg-turbo";
#endif
}

}  // namespace session::image::detail
