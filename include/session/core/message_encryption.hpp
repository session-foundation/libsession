#pragma once

namespace session::core {

/// How a one-to-one message was encrypted: what its envelope used, as received, or what it was
/// sent to its recipient with.  The values are stored, and carried in a sync copy's DataMessage:
/// never renumber them.
enum class MessageEncryption {
    v1 = 1,        ///< The v1 protobuf envelope, to the recipient's long-term key.
    v2_basic = 2,  ///< A v2 message without PFS: the non-PFS fallback, to the long-term key.
    v2_pfs = 3,    ///< A v2 message with PFS+PQ (X-Wing), to the recipient's published account key.
};

}  // namespace session::core
