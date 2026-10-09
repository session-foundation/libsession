#pragma once

#include <cstddef>
#include <type_traits>

namespace session {

// nettle 4.0 dropped the length argument from the *_digest functions, which now always write the
// full digest.  We build against both a distro nettle 3 and the vendored nettle 4, so dispatch on
// whichever signature the nettle in use declares rather than on a version macro.  Every call site
// asks for the full digest length, which is what nettle 3 needs and what nettle 4 assumes, so the
// two spellings compute the same thing.
template <auto digest, typename Ctx, typename Out>
void nettle_digest(Ctx* ctx, std::size_t length, Out* out) {
    if constexpr (std::is_invocable_v<decltype(digest), Ctx*, std::size_t, Out*>)
        digest(ctx, length, out);
    else
        digest(ctx, out);
}

}  // namespace session
