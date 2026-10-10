#pragma once

#include <string_view>

/// The `Error::code` values Core reports, on the same terms as `client::err`: dotted, grouped by
/// the object that failed, and an open set a caller falls back to the message for.
///
/// Client reports some of these too, when what failed was Core's to do, and names them in
/// `client::err` alongside its own.
namespace session::core::err {

/// There is no network attached, so nothing that needs one can be done.
inline constexpr std::string_view network_unavailable = "network.unavailable";

/// The swarm did not store what was sent: it refused it, timed out, or could not be reached.
/// Trying again may work; the message says which.
inline constexpr std::string_view store_failed = "swarm.store_failed";

/// This device is already in the account's device group, so there is nothing to ask to join.
inline constexpr std::string_view already_registered = "device.already_registered";

/// No device group with the identifier asked about is in the swarm, as far as this device has seen:
/// never seen at all, or its messages have since expired.
inline constexpr std::string_view unknown_group = "device.unknown_group";

/// Where this device stands is not known yet -- no fetch has completed this run -- and the call
/// depends on it.  See `Devices::membership`.
inline constexpr std::string_view membership_unknown = "device.membership_unknown";

/// This device was removed from its group, or displaced from it (see `device::Membership`), and
/// must come back under a new device identity before it can do this.
inline constexpr std::string_view removed = "device.removed";

}  // namespace session::core::err
