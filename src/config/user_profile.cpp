#include "session/config/user_profile.h"

#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_sign_ed25519.h>

#include "internal.hpp"
#include "session/config/contacts.hpp"
#include "session/config/error.h"
#include "session/config/pro.h"
#include "session/config/pro.hpp"
#include "session/config/user_profile.hpp"
#include "session/export.h"
#include "session/types.hpp"

using namespace session::config;

UserProfile::UserProfile(
        std::span<const unsigned char> ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped) {
    init(dumped, std::nullopt, std::nullopt);
    load_key(ed25519_secretkey);
}

std::optional<std::string_view> UserProfile::get_name() const {
    if (auto* s = data["n"].string(); s && !s->empty())
        return *s;
    return std::nullopt;
}

void UserProfile::set_name(std::string_view new_name) {
    if (new_name.size() > contact_info::MAX_NAME_LENGTH)
        throw std::invalid_argument{"Invalid profile name: exceeds maximum length"};

    auto current_name = get_name();
    if (current_name && *current_name == new_name)
        return;

    set_nonempty_str(data["n"], new_name);

    const auto target_timestamp = (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
    data[target_timestamp] = ts_now();
}
void UserProfile::set_name_truncated(std::string new_name) {
    set_name(utf8_truncate(std::move(new_name), contact_info::MAX_NAME_LENGTH));
}

profile_pic UserProfile::get_profile_pic() const {
    profile_pic pic{};

    const bool use_primary_keys = (data["t"].integer_or(0) >= data["T"].integer_or(0));
    const auto url_key = (use_primary_keys ? "p" : "P");
    const auto key_key = (use_primary_keys ? "q" : "Q");

    if (auto* url = data[url_key].string(); url && !url->empty())
        pic.url = *url;
    if (auto* key = data[key_key].string(); key && key->size() == 32)
        pic.key.assign(
                reinterpret_cast<const unsigned char*>(key->data()),
                reinterpret_cast<const unsigned char*>(key->data()) + 32);
    return pic;
}

void UserProfile::set_profile_pic(std::string_view url, std::span<const unsigned char> key) {
    auto current_url = data["p"].string_view_or("");
    auto current_key_str = data["q"].string_view_or("");
    std::string_view new_key_str{reinterpret_cast<const char*>(key.data()), key.size()};
    bool changed = (current_url != url) || (current_key_str != new_key_str);

    if (!changed)
        return;

    set_pair_if(!url.empty() && key.size() == 32, data["p"], url, data["q"], key);

    // If the profile was removed then we should remove the "reupload" version as well
    if (url.empty() || key.size() != 32)
        set_reupload_profile_pic({});

    data["t"] = ts_now();
}

void UserProfile::set_profile_pic(profile_pic pic) {
    set_profile_pic(pic.url, pic.key);
}

void UserProfile::set_reupload_profile_pic(
        std::string_view url, std::span<const unsigned char> key) {
    auto current_url = data["P"].string_view_or("");
    auto current_key_str = data["Q"].string_view_or("");
    std::string_view new_key_str{reinterpret_cast<const char*>(key.data()), key.size()};
    bool changed = (current_url != url) || (current_key_str != new_key_str);

    if (!changed)
        return;

    set_pair_if(!url.empty() && key.size() == 32, data["P"], url, data["Q"], key);
    data["T"] = ts_now();
}

void UserProfile::set_reupload_profile_pic(profile_pic pic) {
    set_reupload_profile_pic(pic.url, pic.key);
}

void UserProfile::set_nts_priority(int priority) {
    set_nonzero_int(data["+"], priority);
}

int UserProfile::get_nts_priority() const {
    return data["+"].integer_or(0);
}

void UserProfile::set_nts_expiry(std::chrono::seconds expiry) {
    set_positive_int(data["e"], expiry.count());
}

std::optional<std::chrono::seconds> UserProfile::get_nts_expiry() const {
    if (auto* e = data["e"].integer(); e && *e > 0)
        return std::chrono::seconds{*e};
    return std::nullopt;
}

void UserProfile::set_blinded_msgreqs(std::optional<bool> value) {
    std::optional<bool> current_value;
    if (data["M"].exists())
        current_value = static_cast<bool>(data["M"].integer_or(0));

    if (current_value == value)
        return;

    if (!value)
        data["M"].erase();
    else
        data["M"] = static_cast<int>(*value);

    const auto target_timestamp = (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
    data[target_timestamp] = ts_now();
}

std::optional<bool> UserProfile::get_blinded_msgreqs() const {
    if (auto* M = data["M"].integer())
        return static_cast<bool>(*M);
    return std::nullopt;
}

std::chrono::sys_seconds UserProfile::get_profile_updated() const {
    if (auto t = data["t"].sys_seconds()) {
        if (auto T = data["T"].sys_seconds(); T && *T > *t)
            return *T;
        return *t;
    }
    return std::chrono::sys_seconds{};
}

std::optional<ProConfig> UserProfile::get_pro_config() const {
    std::optional<ProConfig> result = {};
    if (auto* s = data["s"].string()) {
        ProConfig pro = {};
        if (pro.load(*s))
            result = std::move(pro);
    }
    return result;
}

void UserProfile::set_pro_config(const ProConfig& pro) {
    std::optional<ProConfig> curr = get_pro_config();
    if (!curr || *curr != pro) {
        // Store the whole credential as one opaque, bt-encoded value so it merges atomically: a
        // proof split across sibling config keys could have its signature stitched onto a different
        // update's fields (see ProConfig). A single string swap can't slice.
        data["s"] = pro.serialize();

        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }

    // A live proof means any in-flight purchase has resolved: clear the prepaid marker.
    if (pro.proof.expiry_at > ts_now() && data["I"].exists())
        data["I"].erase();
}

bool UserProfile::remove_pro_config() {
    bool result = data["s"].exists();
    data["s"].erase();
    return result;
}

session::ProProfileBitset UserProfile::get_profile_bitset() const {
    ProProfileBitset result = {};
    if (const config::set* set = data["f"].set())
        result.data = bitset_from_set_of_int64_or_0(*set);
    return result;
}

void UserProfile::set_pro_badge(bool enabled) {
    auto feature = SESSION_PROTOCOL_PRO_PROFILE_FEATURES_PRO_BADGE;
    bool dirtied = enabled ? data["f"].set_insert(feature) : data["f"].set_erase(feature);
    if (dirtied) {
        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }
}

void UserProfile::set_animated_avatar(bool enabled) {
    auto feature = SESSION_PROTOCOL_PRO_PROFILE_FEATURES_ANIMATED_AVATAR;
    bool dirtied = enabled ? data["f"].set_insert(feature) : data["f"].set_erase(feature);
    if (dirtied) {
        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }
}

std::optional<std::chrono::sys_seconds> UserProfile::get_pro_access_expiry() const {
    if (auto* E = data["E"].integer()) {
        int64_t secs = *E;
        // Backwards compatibility: older clients stored this as epoch *milliseconds*. A seconds
        // value won't reach 1e12 until the year ~33658, while a millisecond value is ~1.7e12 today,
        // so treat anything past that threshold as milliseconds and convert.
        if (secs > 1'000'000'000'000)
            secs /= 1000;
        return std::chrono::sys_seconds{std::chrono::seconds{secs}};
    }
    return std::nullopt;
}

void UserProfile::set_pro_access_expiry(std::optional<std::chrono::sys_seconds> access_expiry_ts) {
    if (access_expiry_ts)
        data["E"] = epoch_seconds(*access_expiry_ts);
    else {
        data["E"].erase();
        // `G` is only meaningful as `E + G`, so it must never outlive the `E` it was paired with:
        // a stranded `G` would silently pair with whatever the *next* `E` write happens to be, and
        // that next write is usually a proof outcome, which carries no grace of its own to correct
        // it with.  Enforced here rather than left to callers because clearing `E` is the common
        // case (the proof-outcome clears), and a rule spread across every call site is one a new
        // call site inherits wrongly.
        data["G"].erase();
        // `A` describes the subscription `E` denotes, so the same argument applies: a renewing flag
        // with no expiry beside it describes a subscription that is not there.  Every caller that
        // clears `E` is handling an account with no entitlement -- a proof cleared, a proof
        // revoked, or a non-positive `expiry_ts` -- and none of those is auto-renewing, so there is
        // no state in which the flag should survive its expiry.
        //
        // Without this the three keys are only coherent because every *consumer* happens to test
        // `E` before reading `A`.  That is true today on all three clients and it is not a property
        // anything enforces; making the write side maintain the invariant is what stops the next
        // consumer inheriting the obligation without knowing it has one.
        data["A"].erase();
    }

    // Confirming a live entitlement means any in-flight purchase resolved, and any long-stale
    // refund request is moot -- opportunistically clear both (we're already writing E anyway).
    if (access_expiry_ts && *access_expiry_ts > ts_now()) {
        if (data["I"].exists())
            data["I"].erase();
        if (auto* R = data["R"].integer(); R && std::chrono::sys_seconds{std::chrono::seconds{*R}} <
                                                        ts_now() - std::chrono::weeks{1})
            data["R"].erase();
    }
}

bool UserProfile::get_pro_auto_renewing() const {
    return data["A"].integer_or(0) != 0;
}

void UserProfile::set_pro_auto_renewing(bool auto_renewing) {
    // Presence-only: store 1 when auto-renewing, erase otherwise (absent == terminal/unknown). No
    // t/T bump -- this is backend-derived pro state (like E/I/R), not a user-initiated profile
    // edit.
    set_nonzero_int(data["A"], auto_renewing);
}

std::chrono::seconds UserProfile::get_pro_grace_period() const {
    return std::chrono::seconds{data["G"].integer_or(0)};
}

void UserProfile::set_pro_grace_period(std::chrono::seconds grace) {
    // Omitted when zero: the backend sends 0 whenever the subscription isn't auto-renewing, and
    // `E + 0 == E`, so an absent key and a stored zero describe the same account.  Set alongside
    // `E`; no t/T bump -- backend-derived pro state, like E/I/R/A.
    set_nonzero_int(data["G"], grace.count() > 0 ? grace.count() : 0);
}

std::optional<std::chrono::sys_seconds> UserProfile::get_refund_requested() const {
    if (auto* R = data["R"].integer()) {
        std::chrono::sys_seconds when{std::chrono::seconds{*R}};
        // Ignore stale values: a request more than a week old is treated as absent, so a flag some
        // client forgot to clear cannot linger indefinitely across the account's devices.
        if (when >= ts_now() - std::chrono::weeks{1})
            return when;
    }
    return std::nullopt;
}

void UserProfile::set_refund_requested(std::optional<std::chrono::sys_seconds> when) {
    if (when)
        data["R"] = epoch_seconds(*when);
    else
        data["R"].erase();

    // Stamp the profile-updated timestamp so the change is time-ordered across devices.
    const auto target_timestamp = (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
    data[target_timestamp] = ts_now();
}

std::optional<std::chrono::sys_seconds> UserProfile::get_pro_prepaid() const {
    if (auto* I = data["I"].integer()) {
        std::chrono::sys_seconds when{std::chrono::seconds{*I}};
        // Ignore a stale marker (a purchase that never propagated) so devices don't poll forever.
        if (when >= ts_now() - std::chrono::weeks{1})
            return when;
    }
    return std::nullopt;
}

void UserProfile::set_pro_prepaid(std::optional<std::chrono::sys_seconds> when) {
    bool changed = false;
    if (!when) {
        if (data["I"].exists()) {
            data["I"].erase();
            changed = true;
        }
    } else {
        // Only mark a purchase pending if the account isn't already entitled to Pro (a live proof
        // or a still-future access expiry); otherwise there's nothing to poll for.
        bool already_pro = get_pro_config().has_value();
        if (!already_pro)
            if (auto e = get_pro_access_expiry(); e && *e > ts_now())
                already_pro = true;
        if (!already_pro) {
            data["I"] = epoch_seconds(*when);
            changed = true;
        }
    }
    if (changed) {
        const auto target_timestamp =
                (data["t"].integer_or(0) >= data["T"].integer_or(0) ? "t" : "T");
        data[target_timestamp] = ts_now();
    }
}

std::optional<std::chrono::sys_seconds> UserProfile::pro_renewal_target(
        std::chrono::sys_seconds now) const {
    auto pro_config = get_pro_config();
    if (!pro_config) {
        // No proof credential to renew, but still (re)fetch if entitlement is signalled another
        // way:
        //  - a purchase in flight (the prepaid marker), or
        //  - a still-future cached access expiry: we're entitled yet hold no proof to attach. `s`
        //    (the credential) and `E` (the access horizon) are independent config keys, so `s` can
        //    be dropped or merge-lost while `E` still carries a live horizon.
        // Otherwise the account simply isn't Pro. Both signals self-terminate the acquire loop: the
        // prepaid marker ages out via its 1-week read gate; a stale-but-future `E` resolves when a
        // fetch returns not_subscribed and the client clears `E` (which does not self-age).
        if (get_pro_prepaid())
            return now;
        if (auto access = get_pro_access_expiry(); access && *access > now)
            return now;
        return std::nullopt;
    }
    auto expiry = pro_config->proof.expiry_at;
    if (expiry <= now)
        // Expired proof: always re-check with the backend. The subscription may have auto-renewed
        // (possibly without this device's knowledge -- our cached access expiry can't be trusted to
        // reflect a renewal we were offline for), so E is not a reliable gate here. If the backend
        // authoritatively reports the account is not Pro, the client clears the config credential
        // and pushes that, ending the loop (next evaluation: no proof, no prepaid -> nullopt).
        return now;

    // Otherwise renew preemptively PRO_RENEWAL_LEAD before the proof expires, but only while
    // entitlement clearly continues (access expiry at least that far ahead); a still-valid proof
    // with no continuing entitlement is left to ride out.
    auto access = get_pro_access_expiry();
    if (!access || *access - now <= PRO_RENEWAL_LEAD)
        return std::nullopt;

    // The nudges below are best-effort: they only make it *less likely* that two devices near a
    // rotating-seed period boundary race on the same renewal. A genuine collision is still resolved
    // by config resolution, so none of this needs to be airtight.
    auto near_boundary = [](std::chrono::sys_seconds t) {
        auto off = t.time_since_epoch() % PRO_ROTATING_SEED_PERIOD;
        return off <= 15s || off >= PRO_ROTATING_SEED_PERIOD - 15s;
    };

    auto target = expiry - PRO_RENEWAL_LEAD;
    // The scheduled target is shared (derived from the proof's expiry), so nudging it off a
    // boundary keeps every device on the same side of it when the renewal comes due.
    if (near_boundary(target))
        target -= 30s;

    // If the renewal is already due but *now* sits right at a boundary, defer it instead of
    // renewing at the ambiguous instant, so a device cleanly on one side can renew and propagate
    // its config first; failing that we re-poll past the boundary. Only while the deferred time
    // still leaves enough of the current proof's validity.
    if (target <= now && near_boundary(now) &&
        expiry - (now + PRO_RENEWAL_BOUNDARY_DEFER) >= PRO_RENEWAL_BOUNDARY_MIN_VALIDITY)
        return now + PRO_RENEWAL_BOUNDARY_DEFER;

    return target;
}

extern "C" {

using namespace session;
using namespace session::config;

LIBSESSION_C_API const size_t PROFILE_PIC_MAX_URL_LENGTH = profile_pic::MAX_URL_LENGTH;

LIBSESSION_C_API int user_profile_init(
        config_object** conf,
        const unsigned char* ed25519_secretkey_bytes,
        const unsigned char* dumpstr,
        size_t dumplen,
        char* error) {
    return c_wrapper_init<UserProfile>(conf, ed25519_secretkey_bytes, dumpstr, dumplen, error);
}

LIBSESSION_C_API const char* user_profile_get_name(const config_object* conf) {
    if (auto s = unbox<UserProfile>(conf)->get_name())
        return s->data();
    return nullptr;
}

LIBSESSION_C_API int user_profile_set_name(config_object* conf, const char* name) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox<UserProfile>(conf)->set_name(name);
                return 0;
            },
            static_cast<int>(SESSION_ERR_BAD_VALUE));
}

LIBSESSION_C_API user_profile_pic user_profile_get_pic(const config_object* conf) {
    user_profile_pic p;
    if (auto pic = unbox<UserProfile>(conf)->get_profile_pic()) {
        copy_c_str(p.url, pic.url);
        std::memcpy(p.key, pic.key.data(), 32);
    } else {
        p.url[0] = 0;
    }
    return p;
}

LIBSESSION_C_API int user_profile_set_pic(config_object* conf, user_profile_pic pic) {
    std::string_view url{pic.url};
    std::span<const unsigned char> key;
    if (!url.empty())
        key = {pic.key, 32};

    return wrap_exceptions(
            conf,
            [&] {
                unbox<UserProfile>(conf)->set_profile_pic(url, key);
                return 0;
            },
            static_cast<int>(SESSION_ERR_BAD_VALUE));
}

LIBSESSION_C_API int user_profile_set_reupload_pic(config_object* conf, user_profile_pic pic) {
    std::string_view url{pic.url};
    std::span<const unsigned char> key;
    if (!url.empty())
        key = {pic.key, 32};

    return wrap_exceptions(
            conf,
            [&] {
                unbox<UserProfile>(conf)->set_reupload_profile_pic(url, key);
                return 0;
            },
            static_cast<int>(SESSION_ERR_BAD_VALUE));
}

LIBSESSION_C_API int user_profile_get_nts_priority(const config_object* conf) {
    return unbox<UserProfile>(conf)->get_nts_priority();
}

LIBSESSION_C_API void user_profile_set_nts_priority(config_object* conf, int priority) {
    unbox<UserProfile>(conf)->set_nts_priority(priority);
}

LIBSESSION_C_API int user_profile_get_nts_expiry(const config_object* conf) {
    return unbox<UserProfile>(conf)->get_nts_expiry().value_or(0s).count();
}

LIBSESSION_C_API void user_profile_set_nts_expiry(config_object* conf, int expiry) {
    unbox<UserProfile>(conf)->set_nts_expiry(std::max(0, expiry) * 1s);
}

LIBSESSION_C_API int user_profile_get_blinded_msgreqs(const config_object* conf) {
    if (auto opt = unbox<UserProfile>(conf)->get_blinded_msgreqs())
        return static_cast<int>(*opt);
    return -1;
}

LIBSESSION_C_API void user_profile_set_blinded_msgreqs(config_object* conf, int enabled) {
    std::optional<bool> val;
    if (enabled >= 0)
        val = static_cast<bool>(enabled);
    unbox<UserProfile>(conf)->set_blinded_msgreqs(std::move(val));
}

LIBSESSION_C_API int64_t user_profile_get_profile_updated(config_object* conf) {
    return epoch_seconds(unbox<UserProfile>(conf)->get_profile_updated());
}

LIBSESSION_C_API bool user_profile_get_pro_config(const config_object* conf, pro_pro_config* pro) {
    if (auto val = unbox<UserProfile>(conf)->get_pro_config()) {
        static_assert(sizeof pro->proof.revocation_tag == sizeof(val->proof.revocation_tag));
        static_assert(sizeof pro->proof.rotating_pubkey == sizeof(val->proof.rotating_pubkey));
        static_assert(sizeof pro->proof.sig == sizeof(val->proof.sig));
        std::memcpy(
                pro->proof.revocation_tag.data,
                val->proof.revocation_tag.data(),
                val->proof.revocation_tag.size());
        std::memcpy(
                pro->proof.rotating_pubkey.data,
                val->proof.rotating_pubkey.data(),
                val->proof.rotating_pubkey.size());
        pro->proof.expiry_ts = epoch_seconds(val->proof.expiry_at);
        std::memcpy(pro->proof.sig.data, val->proof.sig.data(), val->proof.sig.size());
        std::memcpy(
                pro->rotating_privkey.data,
                val->rotating_privkey.data(),
                val->rotating_privkey.size());
        return true;
    }
    return false;
}

LIBSESSION_C_API void user_profile_set_pro_config(config_object* conf, const pro_pro_config* pro) {
    ProConfig val = {};
    std::memcpy(
            val.proof.revocation_tag.data(),
            pro->proof.revocation_tag.data,
            val.proof.revocation_tag.size());
    std::memcpy(
            val.proof.rotating_pubkey.data(),
            pro->proof.rotating_pubkey.data,
            val.proof.rotating_pubkey.size());
    val.proof.expiry_at = as_sys_seconds(pro->proof.expiry_ts);
    std::memcpy(val.proof.sig.data(), pro->proof.sig.data, val.proof.sig.size());
    std::memcpy(
            val.rotating_privkey.data(), pro->rotating_privkey.data, val.rotating_privkey.size());
    unbox<UserProfile>(conf)->set_pro_config(val);
}

LIBSESSION_C_API bool user_profile_remove_pro_config(config_object* conf) {
    return unbox<UserProfile>(conf)->remove_pro_config();
}

LIBSESSION_C_API session_protocol_pro_profile_bitset
user_profile_get_pro_features(const config_object* conf) {
    session_protocol_pro_profile_bitset result = {};
    result.data = unbox<UserProfile>(conf)->get_profile_bitset().data;
    return result;
}

LIBSESSION_C_API void user_profile_set_pro_badge(config_object* conf, bool enabled) {
    unbox<UserProfile>(conf)->set_pro_badge(enabled);
}

LIBSESSION_C_API void user_profile_set_animated_avatar(config_object* conf, bool enabled) {
    unbox<UserProfile>(conf)->set_animated_avatar(enabled);
}

LIBSESSION_C_API int64_t user_profile_get_pro_access_expiry(const config_object* conf) {
    if (auto expiry = unbox<UserProfile>(conf)->get_pro_access_expiry())
        return epoch_seconds(*expiry);
    return 0;
}

LIBSESSION_C_API void user_profile_set_pro_access_expiry(
        config_object* conf, int64_t access_expiry_ts) {
    if (access_expiry_ts <= 0)
        unbox<UserProfile>(conf)->set_pro_access_expiry(std::nullopt);
    else
        unbox<UserProfile>(conf)->set_pro_access_expiry(as_sys_seconds(access_expiry_ts));
}

LIBSESSION_C_API int user_profile_get_pro_auto_renewing(const config_object* conf) {
    return unbox<UserProfile>(conf)->get_pro_auto_renewing() ? 1 : 0;
}

LIBSESSION_C_API void user_profile_set_pro_auto_renewing(config_object* conf, int auto_renewing) {
    unbox<UserProfile>(conf)->set_pro_auto_renewing(auto_renewing != 0);
}

LIBSESSION_C_API int64_t user_profile_get_pro_grace_period(const config_object* conf) {
    return unbox<UserProfile>(conf)->get_pro_grace_period().count();
}

LIBSESSION_C_API void user_profile_set_pro_grace_period(
        config_object* conf, int64_t grace_seconds) {
    unbox<UserProfile>(conf)->set_pro_grace_period(std::chrono::seconds{grace_seconds});
}

LIBSESSION_C_API int64_t user_profile_get_refund_requested(const config_object* conf) {
    if (auto when = unbox<UserProfile>(conf)->get_refund_requested())
        return epoch_seconds(*when);
    return 0;
}

LIBSESSION_C_API void user_profile_set_refund_requested(config_object* conf, int64_t refund_ts) {
    if (refund_ts <= 0)
        unbox<UserProfile>(conf)->set_refund_requested(std::nullopt);
    else
        unbox<UserProfile>(conf)->set_refund_requested(as_sys_seconds(refund_ts));
}

LIBSESSION_C_API int64_t user_profile_get_pro_prepaid(const config_object* conf) {
    if (auto when = unbox<UserProfile>(conf)->get_pro_prepaid())
        return epoch_seconds(*when);
    return 0;
}

LIBSESSION_C_API void user_profile_set_pro_prepaid(config_object* conf, int64_t prepaid_ts) {
    if (prepaid_ts <= 0)
        unbox<UserProfile>(conf)->set_pro_prepaid(std::nullopt);
    else
        unbox<UserProfile>(conf)->set_pro_prepaid(as_sys_seconds(prepaid_ts));
}

LIBSESSION_C_API int64_t
user_profile_get_pro_renewal_target(const config_object* conf, int64_t now) {
    if (auto t = unbox<UserProfile>(conf)->pro_renewal_target(as_sys_seconds(now)))
        return epoch_seconds(*t);
    return 0;
}

}  // extern "C"
