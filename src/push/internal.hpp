#pragma once

#include <session/core.hpp>

namespace session::push::detail {

/// Makes the recorded subscription due, so the next `Notifications::subscribe` sends rather than
/// finding it current: for when a push shows the push server is using a key we no longer hold.
/// Call on Core's loop.
void mark_subscription_due(core::Core& core);

}  // namespace session::push::detail
