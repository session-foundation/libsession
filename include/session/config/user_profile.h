#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include "pro.h"
#include "profile_pic.h"

/// API: user_profile/user_profile_init
///
/// Constructs a user profile config object and sets a pointer to it in `conf`.
///
/// When done with the object the `config_object` must be destroyed by passing the pointer to
/// config_free() (in `session/config/base.h`).
///
/// Declaration:
/// ```cpp
/// INT user_profile_init(
///     [out]   config_object**         conf,
///     [in]    const unsigned char*    ed25519_secretkey,
///     [in]    const unsigned char*    dump,
///     [in]    size_t                  dumplen,
///     [out]   char*                   error
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `ed25519_secretkey` -- [in] must be the 32-byte secret key seed value.  (You can also pass the
/// pointer to the beginning of the 64-byte value libsodium calls the "secret key" as the first 32
/// bytes of that are the seed).  This field cannot be null.
/// - `dump` -- [in] if non-NULL this restores the state from the dumped byte string produced by a
/// past instantiation's call to `dump()`.  To construct a new, empty profile this should be NULL.
/// - `dumplen` -- [in] the length of `dump` when restoring from a dump, or 0 when `dump` is NULL.
/// - `error` -- [out] the pointer to a buffer in which we will write an error string if an error
/// occurs; error messages are discarded if this is given as NULL.  If non-NULL this must be a
/// buffer of at least 256 bytes.
///
/// Outputs:
/// - `int` -- Returns 0 on success; returns a non-zero error code and write the exception message
/// as a C-string into `error` (if not NULL) on failure.
LIBSESSION_EXPORT int user_profile_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey,
        const unsigned char* dump,
        size_t dumplen,
        char* error) LIBSESSION_WARN_UNUSED;

/// API: user_profile/user_profile_get_name
///
/// Returns a pointer to the currently-set name (null-terminated), or NULL if there is no name at
/// all.  Should be copied right away as the pointer may not remain valid beyond other API calls.
///
/// Declaration:
/// ```cpp
/// CONST CHAR* user_profile_get_name(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `char*` -- Pointer to the currently-set name as a null-terminated string, or NULL if there is
/// no name
LIBSESSION_EXPORT const char* user_profile_get_name(const config_object* conf);

/// API: user_profile/user_profile_set_name
///
/// Sets the user profile name to the null-terminated C string.  Returns 0 on success, non-zero on
/// error (and sets the config_object's error string).
///
/// Declaration:
/// ```cpp
/// INT user_profile_set_name(
///     [in]    config_object*  conf,
///     [in]    const char*     name
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `name` -- [in] Pointer to the name as a null-terminated C string
///
/// Outputs:
/// - `int` -- Returns 0 on success, non-zero on error
LIBSESSION_EXPORT int user_profile_set_name(config_object* conf, const char* name);

/// API: user_profile/user_profile_get_pic
///
/// Obtains the current profile pic.  The pointers in the returned struct will be NULL if a profile
/// pic is not currently set, and otherwise should be copied right away (they will not be valid
/// beyond other API calls on this config object).  The returned value will be the latest profile
/// pic between when the user last set their profile and when it was last re-uploaded.
///
/// Declaration:
/// ```cpp
/// USER_PROFILE_PIC user_profile_get_pic(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `user_profile_pic` -- Pointer to the currently-set profile pic
LIBSESSION_EXPORT user_profile_pic user_profile_get_pic(const config_object* conf);

/// API: user_profile/user_profile_set_pic
///
/// Sets a user profile pic
///
/// Declaration:
/// ```cpp
/// INT user_profile_set_pic(
///     [in]    config_object*      conf,
///     [in]    user_profile_pic    pic
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pic` -- [in] Pointer to the pic
///
/// Outputs:
/// - `int` -- Returns 0 on success, non-zero on error
LIBSESSION_EXPORT int user_profile_set_pic(config_object* conf, user_profile_pic pic);

/// API: user_profile/user_profile_set_reupload_pic
///
/// Sets a user profile pic when reuploading
///
/// Declaration:
/// ```cpp
/// INT user_profile_set_reupload_pic(
///     [in]    config_object*      conf,
///     [in]    user_profile_pic    pic
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pic` -- [in] Pointer to the pic
///
/// Outputs:
/// - `int` -- Returns 0 on success, non-zero on error
LIBSESSION_EXPORT int user_profile_set_reupload_pic(config_object* conf, user_profile_pic pic);

/// API: user_profile/user_profile_get_nts_priority
///
/// Gets the current note-to-self priority level. Will be negative for hidden, 0 for unpinned, and >
/// 0 for pinned (with higher value = higher priority).
///
/// Declaration:
/// ```cpp
/// INT user_profile_get_nts_priority(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- Returns the priority level
LIBSESSION_EXPORT int user_profile_get_nts_priority(const config_object* conf);

/// API: user_profile/user_profile_set_nts_priority
///
/// Sets the current note-to-self priority level. Set to -1 for hidden; 0 for unpinned, and > 0 for
/// higher priority in the conversation list.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_nts_priority(
///     [in]    config_object*      conf,
///     [in]    int                 priority
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `priority` -- [in] Integer of the priority
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void user_profile_set_nts_priority(config_object* conf, int priority);

/// API: user_profile/user_profile_get_nts_expiry
///
/// Gets the Note-to-self message expiry timer (seconds).  Returns 0 if not set.
///
/// Declaration:
/// ```cpp
/// INT user_profile_get_nts_expiry(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- Returns the expiry timer in seconds. Returns 0 if not set
LIBSESSION_EXPORT int user_profile_get_nts_expiry(const config_object* conf);

/// API: user_profile/user_profile_set_nts_expiry
///
/// Sets the Note-to-self message expiry timer (seconds).  Setting 0 (or negative) will clear the
/// current timer.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_nts_expiry(
///     [in]    config_object*      conf,
///     [in]    int                 expiry
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `expiry` -- [in] Integer of the expiry timer in seconds
LIBSESSION_EXPORT void user_profile_set_nts_expiry(config_object* conf, int expiry);

/// API: user_profile/user_profile_get_blinded_msgreqs
///
/// Returns true if blinded message requests should be retrieved (from SOGS servers), false if they
/// should be ignored.
///
/// Declaration:
/// ```cpp
/// INT user_profile_get_blinded_msgreqs(
///     [in]    const config_object*    conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- Will be -1 if the config does not have the value explicitly set, 0 if the setting is
///   explicitly disabled, and 1 if the setting is explicitly enabled.
LIBSESSION_EXPORT int user_profile_get_blinded_msgreqs(const config_object* conf);

/// API: user_profile/user_profile_set_blinded_msgreqs
///
/// Sets whether blinded message requests should be retrieved from SOGS servers.  Set to 1 (or any
/// positive value) to enable; 0 to disable; and -1 to clear the setting.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_blinded_msgreqs(
///     [in]    config_object*      conf,
///     [in]    int                 enabled
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `enabled` -- [in] true if they should be enabled, false if disabled
///
/// Outputs:
/// - `void` -- Returns Nothing
LIBSESSION_EXPORT void user_profile_set_blinded_msgreqs(config_object* conf, int enabled);

/// API: user_profile/user_profile_get_profile_updated
///
/// Returns the timestamp that the user last updated their profile information; or `0` if it's
/// never been updated.  This value will return the latest timestamp between when the user last
/// set their profile and when it was last re-uploaded.
///
/// Inputs: None
///
/// Outputs:
/// - `int64_t` - timestamp (unix seconds) that the user last updated their public profile
/// information.  Will be `0` if it's never been updated.
LIBSESSION_EXPORT int64_t user_profile_get_profile_updated(config_object* conf);

/// API: user_profile/user_profile_get_pro_config
///
/// Get the Pro data for the user profile if it exists which includes the users rotating private key
/// and their last authorised proof.
///
/// Declaration:
/// ```cpp
/// BOOL user_profile_get_pro_config(
///     [in]    const config_object* conf
///     [out]   pro_pro*             pro
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pro` -- [out] Pointer to the pro object where the retrieved details are written
///
/// Outputs:
/// - `bool` -- True if the user profile had Pro data associated with it. Otherwise false and the
///   pro structure will remain untouched.
LIBSESSION_EXPORT bool user_profile_get_pro_config(const config_object* conf, pro_pro_config* pro);

/// API: user_profile/user_profile_set_pro_config
///
/// Update the pro data associated with the user profile.
///
/// Declaration:
/// ```cpp
/// VOID user_profile_set_pro_config(
///     [in]    config_object* conf,
///     [in]    pro_pro*       pro
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `pro` -- [in] Pointer to the Pro data to write to the user profile
///
/// Outputs:
/// - `void` -- Returns nothing
LIBSESSION_EXPORT void user_profile_set_pro_config(config_object* conf, const pro_pro_config* pro);

/// API: user_profile/user_profile_remove_pro_config
///
/// Remove the Session Pro components from the user profile.
///
/// Declaration:
/// ```cpp
/// BOOL user_profile_remove_pro_config(
///     [in]    config_object* conf
/// );
/// ```
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `bool` - A flag indicating whether the config had Session Pro components which were removed.
LIBSESSION_EXPORT bool user_profile_remove_pro_config(config_object* conf);

/// API: user_profile/user_profile_get_pro_features
///
/// Retrieves the bitset indicating which pro features the user currently has enabled.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `session_protocol_pro_profile_bitset` - bitset indicating which profile features are enabled.
LIBSESSION_EXPORT session_protocol_pro_profile_bitset
user_profile_get_pro_features(const config_object* conf);

/// API: user_profile/user_profile_set_pro_badge
///
/// Updates the bitset to specify whether the user wants their profile to show the pro badge.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `enabled` -- Flag which specifies whether the user wants the pro badge to appear on their
/// profile or not.
LIBSESSION_EXPORT void user_profile_set_pro_badge(config_object* conf, bool enabled);

/// API: user_profile/user_profile_set_animated_avatar
///
/// Updates the bitset to specify whether the user has an animated profile picture, should be
/// set when uploading a profile picture. Note: This doesn't prevent a users profile picture
/// from animating, it's just a way to more easily synchronise the state between devices when
/// sending messages so we don't need the device to have successfully download the current
/// display picture in order to be able to determine this.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `enabled` -- Flag which specifies whether the users display picture is animated or not.
LIBSESSION_EXPORT void user_profile_set_animated_avatar(config_object* conf, bool enabled);

/// API: user_profile/user_profile_get_pro_access_expiry
///
/// Retrieves the Session Pro access expiry unix timestamp if it has been set, this should generally
/// be the expiry value returned from /get_pro_status.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int64_t` - The unix timestamp in seconds that the users pro access will expire, or 0 if
/// unset.
LIBSESSION_EXPORT int64_t user_profile_get_pro_access_expiry(const config_object* conf);

/// API: user_profile/user_profile_set_pro_access_expiry
///
/// Updates the Session Pro access expiry unix timestamp.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `access_expiry_ts` -- The timestamp (unix epoch seconds) that the users Session Pro access
/// will expire, or 0 to remove the value.
LIBSESSION_EXPORT void user_profile_set_pro_access_expiry(
        config_object* conf, int64_t access_expiry_ts);

/// API: user_profile/user_profile_get_pro_auto_renewing
///
/// Returns whether the account's current Session Pro subscription is auto-renewing. Backend-derived
/// (the `auto_renewing` field on /get_pro_status); set alongside the access expiry.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int` -- 1 if the subscription is known to be auto-renewing, otherwise 0 (terminal, unknown,
///   or not Pro).
LIBSESSION_EXPORT int user_profile_get_pro_auto_renewing(const config_object* conf);

/// API: user_profile/user_profile_set_pro_auto_renewing
///
/// Records whether the current Session Pro subscription is auto-renewing: nonzero stores the flag,
/// 0 clears it (which is also how it is cleared when the subscription lapses).
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `auto_renewing` -- [in] nonzero if auto-renewing, 0 to clear
///
/// Outputs:
/// - `void`
LIBSESSION_EXPORT void user_profile_set_pro_auto_renewing(config_object* conf, int auto_renewing);

/// API: user_profile/user_profile_get_pro_grace_period
///
/// Returns the account's grace period in seconds (`get_pro_status.grace_period_duration`), or 0 if
/// none is stored. Backend-derived and synced alongside the access expiry, so any linked device can
/// compute when coverage actually ends: `access_expiry + grace_period`. The access expiry is the
/// payment-due date -- the instant the term was paid through -- and `[E, E + G)` is the window
/// where the payment is overdue but service continues.
///
/// There is deliberately no companion presence check: the backend sends 0 whenever the
/// subscription is not auto-renewing, so "unset" and "zero" describe the same account and both give
/// `expiry + 0 == expiry`.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int64_t` -- the grace period in seconds, or 0 if unset.
LIBSESSION_EXPORT int64_t user_profile_get_pro_grace_period(const config_object* conf);

/// API: user_profile/user_profile_set_pro_grace_period
///
/// Sets the account's grace period, in seconds. Set alongside `user_profile_set_pro_access_expiry`
/// from each `get_pro_status` response; 0 (or negative) clears it.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `grace_seconds` -- [in] the grace period in seconds, or 0 to clear
///
/// Outputs:
/// - `void`
LIBSESSION_EXPORT void user_profile_set_pro_grace_period(
        config_object* conf, int64_t grace_seconds);

/// API: user_profile/user_profile_get_refund_requested
///
/// Retrieves the timestamp at which the user requested a refund of their current Session Pro
/// subscription.  This state is synced across the user's devices via config (not the Pro backend).
/// A stored value more than a week in the past is ignored (returns 0).
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int64_t` - the unix timestamp (seconds) at which a refund was requested, or 0 if no refund
/// has been requested (or the stored value is stale).
LIBSESSION_EXPORT int64_t user_profile_get_refund_requested(const config_object* conf);

/// API: user_profile/user_profile_set_refund_requested
///
/// Records (or clears) that the user has requested a refund of their current Session Pro
/// subscription, propagating it to the user's other devices via config sync.  The client should
/// clear it (passing 0) when a new subscription begins.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `refund_ts` -- the timestamp (unix epoch seconds) at which the refund was requested, or 0 to
/// clear the refund-requested state.
LIBSESSION_EXPORT void user_profile_set_refund_requested(config_object* conf, int64_t refund_ts);

/// API: user_profile/user_profile_get_pro_prepaid
///
/// Retrieves the timestamp at which a Session Pro purchase was initiated (the "purchase in flight"
/// marker), synced across the user's devices. A stored value more than a week in the past is
/// ignored (returns 0).
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
///
/// Outputs:
/// - `int64_t` - the unix timestamp (seconds) at which a purchase was initiated, or 0 if none is
/// pending (or the stored value is stale).
LIBSESSION_EXPORT int64_t user_profile_get_pro_prepaid(const config_object* conf);

/// API: user_profile/user_profile_set_pro_prepaid
///
/// Records (or clears) that a Session Pro purchase is in flight so the user's other devices poll
/// the backend to pull the entitlement through. A no-op if the account is already Pro; cleared
/// automatically once entitlement lands, or explicitly by passing 0.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `prepaid_ts` -- the timestamp (unix epoch seconds) at which the purchase was initiated, or 0
/// to clear the marker.
LIBSESSION_EXPORT void user_profile_set_pro_prepaid(config_object* conf, int64_t prepaid_ts);

/// API: user_profile/user_profile_get_pro_renewal_target
///
/// Decide when to (re)request a Session Pro proof (see the C++ pro_renewal_target). Given `now`,
/// returns the unix timestamp (seconds) at which a renewal should be attempted -- renew now if it
/// is <= now, otherwise schedule for then -- or 0 if no renewal is needed.
///
/// Inputs:
/// - `conf` -- [in] Pointer to the config object
/// - `now` -- the caller's current unix timestamp (seconds)
///
/// Outputs:
/// - `int64_t` - the renewal-target unix timestamp, or 0 for "no renewal needed".
LIBSESSION_EXPORT int64_t
user_profile_get_pro_renewal_target(const config_object* conf, int64_t now);

#ifdef __cplusplus
}  // extern "C"
#endif
