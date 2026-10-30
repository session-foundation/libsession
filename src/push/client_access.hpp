#pragma once

#include <session/client.hpp>

namespace session::push::detail {

/// Client's result delivery, lent to push: a push operation's result reaches the application the
/// way a Client operation's does, through the Client's dispatcher.  A friend of Client rather than
/// public API, because what it hands out is how Client keeps its own promise to call each result
/// handler exactly once.
class ClientAccess {
  public:
    /// Hands `result` to `cb` through `client`'s dispatcher.  Call on Core's loop, where the
    /// dispatcher lives.
    template <typename Cb, typename R>
    static void report(client::Client& client, Cb& cb, R result) {
        client._report(cb, std::move(result));
    }
};

}  // namespace session::push::detail
