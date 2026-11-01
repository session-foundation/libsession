#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/component.hpp>
#include <session/core/pro.hpp>
#include <session/pro_backend.hpp>

#include "SQLiteCpp/Transaction.h"
#include "session/sqlite.hpp"

namespace session::core {

bool Pro::proof_is_revoked(
        std::span<const std::byte, 32> revocation_tag, std::chrono::sys_seconds unix_ts) {
    return conn().prepared_get<int>(
            "SELECT EXISTS (SELECT 1 FROM pro_revocations"
            " WHERE revocation_tag = ? AND effective_ts <= ?)",
            revocation_tag,
            unix_ts.time_since_epoch().count());
}

/// API: core/Pro::pro_update_revocations
///
/// Update the list of pro revocations.  If the `revocations_ticket` matches the current ticket,
/// this is a no-op.
///
/// Inputs:
/// - `ticket` -- Ticket that describes the version of the revocations. This value comes
///   alongside the revocation list when queried.  This ticket changes whenever the revocation
///   list is updated and is used to identify when an actual update is needed.
/// - `revocations` -- New list of Session Pro revocations.
void Pro::update_revocations(
        uint32_t ticket,
        std::span<const pro_backend::ProRevocationItem> revocations,
        std::chrono::seconds retain_for) {

    if (revocations_ticket_ && ticket == *revocations_ticket_)
        return;

    auto now = session::clock_now_s().time_since_epoch().count();

    auto c = conn();
    auto tx = c.begin_immediate();

    // Upsert each listed revocation, (re)setting its last-seen time to now.
    for (auto st =
                 c.prepared_st("INSERT INTO pro_revocations (revocation_tag, effective_ts, seen_at)"
                               " VALUES (?, ?, ?)"
                               " ON CONFLICT (revocation_tag) DO UPDATE SET"
                               " effective_ts = excluded.effective_ts, seen_at = excluded.seen_at");
         const auto& revoke : revocations) {
        exec_query(st, revoke.revocation_tag, revoke.effective_at.time_since_epoch().count(), now);
        st->reset();
    }

    // Memory-only aging: drop entries not seen within the retain window. Unlike the wire list,
    // absent entries are not deleted immediately -- holding a stale entry is harmless (its random
    // tag never matches a live proof), and retain_for >= the proof-validity window guarantees we
    // never drop an entry while a valid proof could still carry it.
    auto del = c.prepared_st("DELETE FROM pro_revocations WHERE seen_at + ? < ?");
    exec_query(del, retain_for.count(), now);

    revocations_ticket_ = ticket;
    tx.commit();
}

}  // namespace session::core
