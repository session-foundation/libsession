#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/bt_value_producer.h>
#include <oxenc/hex.h>

#include <cassert>
#include <chrono>
#include <cmath>
#include <concepts>
#include <iterator>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/format.hpp>
#include <ranges>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/error_codes.hpp>
#include <session/core/link_sas.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/crypto/mlkem768.hpp>
#include <session/crypto/x25519.hpp>
#include <session/encrypt.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
#include <session/placeholders.hpp>
#include <session/random.hpp>
#include <session/sqlite.hpp>
#include <session/types.hpp>
#include <session/util.hpp>
#include <session/xed25519.hpp>
#include <stdexcept>

#include "../internal-util.hpp"

namespace fmt {

/// Logs a key pair as "X25519[abcd…wxyz], MLKEM768[abcd…wxyz]".
///
/// Out here, rather than beside the type, because a formatter specialization belongs to namespace
/// fmt and `session::core` does not enclose it.  A specialization rather than fmt's ADL `format_as`
/// hook because that hook only reaches non-enum types from fmt 10 onwards, and because this is also
/// the form `std::format` takes.
///
/// Reopening namespace fmt rather than writing this out-of-line as `fmt::formatter<Keys, char>`:
/// gcc 11 does not take the constraints of an out-of-line constrained partial specialization into
/// account and so rejects this one as a redefinition of libquic's `formatter<T, char>` for
/// to_string-ables.
template <std::derived_from<session::core::Devices::XWingKeys> Keys>
struct formatter<Keys, char> : formatter<std::string> {
    auto format(const Keys& k, format_context& ctx) const {
        return formatter<std::string>::format(
                fmt::format("X25519[{:9.4}], MLKEM768[{:9.4}]", k.x25519_pub, k.mlkem768_pub), ctx);
    }
};

}  // namespace fmt

namespace session::core {

using namespace fmt::literals;
using namespace oxen::log::literals;
using namespace session::literals;
using namespace std::literals;

namespace log = oxen::log;
static auto cat = log::Cat("core.dev");

static constexpr auto dev_key = "device_unique_id"sv;

// What this device describes itself as -- description, type, version, and whatever later versions
// add -- encoded as the tail of a record is (see `encode_described`).  The master copy: every
// record of ours is built from it, and nothing the group holds is ever copied back into it, so
// leaving a group and forgetting its devices loses none of it.
static constexpr auto own_info_key = "devices_own_info"sv;

// Set by Globals when it *generates* an account, and cleared once the device group exists.  A
// restored account never sets it: its group, if it has one, belongs to devices we have not met yet.
static constexpr auto establish_key = "devices_establish_group"sv;

static constexpr auto group_id_key = "devices_group_id"sv;

// The creation minute, then 4 random bytes to tell apart groups created in the same one.
static device::GroupId new_group_id() {
    device::GroupId id;
    auto minutes = std::chrono::floor<std::chrono::minutes>(clock_now()).time_since_epoch();
    oxenc::write_host_as_little(static_cast<uint32_t>(minutes.count()), id.value.data());
    random::fill(std::span{id.value}.last<4>());
    return id;
}

// The signed time of the newest message from our group that we could read, of the one we could not
// that displaced us from it, and of the newest we could not that left us unable to tell why, in
// unix milliseconds.
static constexpr auto read_at_key = "devices_group_read_at"sv;
static constexpr auto displaced_key = "devices_group_displaced_at"sv;
static constexpr auto dropped_key = "devices_group_dropped_at"sv;

// The keys seen on -21 that were none of ours when seen, waiting on a fetch of the group to say
// whether they are a rotation or rogue: each the X25519 half then the ML-KEM half, concatenated.
// Kept rather than held in memory because -21 is not handed out twice: a retrieve resumes after
// the last hash it returned, so a key forgotten across a restart would never be judged.
static constexpr auto suspect_pubkeys_key = "devices_suspect_account_pubkeys"sv;

// Set when a tombstone named the group this device was in, until it joins or starts another.
static constexpr auto dissolved_key = "devices_group_dissolved"sv;

// When our current device keys are due to be rotated, in unix milliseconds: picked, jitter and
// all, when they were made, and kept so that the jitter is the same however often it is asked.
static constexpr auto device_rotation_key = "devices_device_rotation_at"sv;

// When the current account key, having reached a device no longer in the group, is to be replaced
// early, in unix milliseconds; see `_early_account_rotation`.
static constexpr auto early_rotation_key = "devices_account_rotation_early_at"sv;

// How long the fetch timer waits to try again after its fetch failed.
static constexpr auto FETCH_RETRY = 1min;

void Devices::init() {
    if (core.globals.get_blob_to(dev_key, self_id))
        log::info(cat, "Loaded existing unique device id: {}", self_id);
    else {
        random::fill(self_id);
        core.globals.set(dev_key, self_id);
        log::info(cat, "Generated new unique device id: {}", self_id);
    }

    // Here rather than where the account is created, for two reasons: this component initialises
    // after Globals, so `self_id` does not exist yet at that point, and the flag is persisted, so
    // an account created by a run that died before reaching this still gets its group.
    establish_group();

    _expiry_timer = jq().add_wakeable([this] { _flush_events(); });
    _fetch_timer = jq().add_wakeable([this] {
        jq().stop(_fetch_timer);
        if (!core.network())
            return;
        // A successful fetch re-arms the timer from what it then finds due; a failed one tries
        // again shortly rather than at once, which with a rotation still overdue would spin.
        core._fetch(
                {config::Namespace::Devices},
                [this, alive = std::weak_ptr<int>{_alive}](bool fetched) {
                    if (!alive.expired() && !fetched)
                        jq().repeat(_fetch_timer, FETCH_RETRY);
                });
    });

    // A request of ours from the last run carries on if the swarm still holds it, or if an
    // admission on it waits for the user.  Otherwise it is withdrawn: lapsed, or never confirmed
    // stored, which leaves us Pending with nothing to wait on.  Withdrawn only here -- a copy that
    // did reach the swarm can still be approved, which leaves us Approved all the same.
    auto newest = _newest_request();
    if (newest && newest->held)
        return;
    if (auto deadline = _own_deadline(); deadline && *deadline > clock_now())
        _arm_expiry(deadline);
    else
        _withdraw_own_request();
}

void Devices::_mark_group_owed() {
    core.globals.set(establish_key, int64_t{1});
}

void Devices::establish_group() {
    if (!core.globals.have_account())
        return;
    if (!core.globals.get_integer(establish_key).value_or(0))
        return;

    // Not inside a transaction of our own: both of these open one.  `active_device_keys` also
    // generates this device's keys if it has none, which is the case being bootstrapped here.
    auto keys = active_device_keys();
    auto& key = keys.front();
    // Mints the account's first shared seed if there is not one yet.
    auto link_x25519 = active_account_keys().front().x25519_pub;

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    // Registered, but at seqno 0: the swarm holds no record of ours yet, so the first push carries
    // seqno 1, built from what we describe ourselves as (see `_own_record`).  `broadcast_needed`
    // marks the state transition: from no device at all to a registered one.
    c.prepared_exec(
            R"(INSERT INTO devices
                (unique_id, state, seqno, timestamp, device_type, description, version,
                 pubkey_mlkem768, pubkey_x25519, broadcast_needed)
               VALUES (?1, ?2, 0, ?3, '', '', 0, ?4, ?5, 1)
               ON CONFLICT(unique_id) DO UPDATE SET
                   state = ?2,
                   broadcast_needed = broadcast_needed + 1,
                   pubkey_mlkem768 = ?4,
                   pubkey_x25519 = ?5)",
            self_id,
            static_cast<int>(device::State::Registered),
            epoch_seconds(clock_now_s()),
            std::as_bytes(std::span{key.mlkem768_pub}),
            std::as_bytes(std::span{key.x25519_pub}));

    // Among the groups we know of from the moment it exists, as every other group we have seen is,
    // rather than only once its first message comes back from the swarm.
    auto group = new_group_id();
    _set_group_id(group);
    _note_read(clock_now_ms());
    auto now = clock_now_s();
    c.prepared_exec(
            "INSERT INTO device_groups (group_id, link_x25519, seen_at, expires_at)"
            " VALUES (?, ?, ?, ?)",
            std::span<const std::byte>{group.value},
            link_x25519,
            epoch_seconds(now),
            epoch_seconds(now + DEVICE_GROUP_TTL));
    core.globals.set(establish_key, int64_t{0});

    tx.commit();

    log::info(cat, "Established device group with this device ({}) as its only member", self_id);
}

std::string Devices::device_id() const {
    return oxenc::to_hex(self_id);
}

template <typename T>
consteval auto KEY_DOMAIN() = delete;
template <>
consteval auto KEY_DOMAIN<Devices::DeviceKeys>() {
    return "SessionDeviceKeys"_bytes;
}
template <>
consteval auto KEY_DOMAIN<Devices::AccountKeys>() {
    return "SessionAccountKeys"_bytes;
}

template <std::derived_from<Devices::XWingKeys> Keys>
static Keys keys_from_seed(std::span<const std::byte, 32> seed) {
    Keys keys;
    auto& [x_sec, x_pub, ml_sec, ml_pub] = static_cast<Devices::XWingKeys&>(keys);

    static_assert(mlkem768::PUBLICKEYBYTES == sizeof(ml_pub));
    static_assert(mlkem768::SECRETKEYBYTES == sizeof(ml_sec));

    // Use SHAKE256 to expand the seed into separate X25519 and MLKEM-768 seeds.  Domain
    // separation is achieved by prepending the domain string before the seed.
    cleared_array<std::byte, mlkem768::SEEDBYTES> ml_seed;
    hash::shake256(KEY_DOMAIN<Keys>(), seed)(x_sec, ml_seed);
    x25519::scalarmult_base(x_pub, x_sec);

    mlkem768::keygen(ml_pub, ml_sec, ml_seed);

    return keys;
}

namespace {

}  // namespace

Devices::DeviceKeys Devices::rotate_device_keys() {
    // We store just one single seed value, then use SHAKE256 to expand it into separate X25519
    // (32B) and MLKEM-768 (64B) seeds.
    cleared_b32 seed;
    random::fill(seed);

    // Call this mainly to ensure that we can successfully produce keys from this seed.
    auto keys = keys_from_seed<DeviceKeys>(seed);

    // Nothing else to update: our record is built from the current keys when next it is published
    // (see `_own_record`).
    auto created = clock_now_s();
    auto c = conn();
    c.prepared_exec(
            "INSERT INTO device_privkeys (created, seed) VALUES (?, ?)",
            epoch_seconds(created),
            seed);
    c.prepared_exec(
            "DELETE FROM device_privkeys WHERE id NOT IN"
            " (SELECT id FROM device_privkeys ORDER BY created DESC, id DESC LIMIT 2)");
    _schedule_device_rotation(created);

    log::info(cat, "New rotating device keys generated: {}", keys);

    return keys;
}

// A delay picked uniformly from [0, KEY_ROTATION_JITTER].
static std::chrono::milliseconds jitter() {
    return std::chrono::milliseconds{random::get_uniform_distribution<int64_t>(
            0, std::chrono::milliseconds{Devices::KEY_ROTATION_JITTER}.count())};
}

sys_ms Devices::_schedule_device_rotation(std::chrono::sys_seconds created) {
    auto due = created + KEY_ROTATION_PERIOD - KEY_ROTATION_JITTER / 2 + jitter();
    core.globals.set(device_rotation_key, epoch_ms(due));
    return due;
}

void Devices::rotate_account_keys() {
    cleared_b32 seed;
    random::fill(seed);
    auto keys = keys_from_seed<AccountKeys>(seed);

    // Created after every key we hold, even within the same second: the newest key wins, with ties
    // going to the lowest seed, so a rotation stamped with the same second as the key it replaces
    // could lose to it -- and after a removal, that would leave current the key the removed device
    // holds.
    auto c = conn();
    c.prepared_exec(
            "INSERT INTO device_account_keys (created, seed, pubkey_mlkem768, pubkey_x25519)"
            " VALUES (MAX(?1, IFNULL((SELECT MAX(created) + 1 FROM device_account_keys), ?1)),"
            "  ?2, ?3, ?4)",
            epoch_seconds(clock_now_s()),
            seed,
            keys.mlkem768_pub,
            keys.x25519_pub);

    log::info(cat, "New account keys generated: {}", keys);
}

std::vector<Devices::DeviceKeys> Devices::active_device_keys() {
    std::vector<DeviceKeys> keys;
    auto c = conn();
    bool have_active = false;
    for (auto [seed, rotated] : c.prepared_results<sqlite::blobn<32>, std::optional<int64_t>>(
                 "SELECT seed, rotated FROM device_privkeys"
                 " ORDER BY rotated DESC NULLS FIRST, created DESC")) {
        auto& k = keys.emplace_back(keys_from_seed<DeviceKeys>(seed));
        if (rotated)
            k.rotated.emplace(std::chrono::seconds{*rotated});
        else
            have_active = true;
    }

    if (!have_active) {
        log::info(cat, "No currently active device keys; generating a new one");
        keys.insert(keys.begin(), rotate_device_keys());
    }

    return keys;
}

std::vector<Devices::AccountKeys> Devices::active_account_keys(
        std::optional<std::span<const std::byte, 2>> key_indicator) {
    auto c = conn();
    SQLite::Transaction tx{c.sql};

    _prune_account_keys();

    std::vector<AccountKeys> keys;
    bool have_active = false;

    auto query_all =
            "SELECT id, created, rotated, seed, pubkey_mlkem768, pubkey_x25519"
            " FROM device_account_keys"
            " ORDER BY rotated DESC NULLS FIRST, created DESC";
    auto query_ki =
            "SELECT id, created, rotated, seed, pubkey_mlkem768, pubkey_x25519"
            " FROM device_account_keys"
            " WHERE key_indicator = ?"
            " ORDER BY rotated DESC NULLS FIRST, created DESC";

    using cols_t = sqlite::IterableStatementWrapper<
            int64_t,
            int64_t,
            std::optional<int64_t>,
            sqlite::blobn<32>,
            sqlite::blobn<mlkem768::PUBLICKEYBYTES>,
            sqlite::blobn<32>>;

    for (auto [id, created, rotated, seed, pk_ml, pk_x] :
         key_indicator ? cols_t{c.prepared_bind(query_ki, *key_indicator)}
                       : cols_t{c.prepared_bind(query_all)}) {
        auto& k = keys.emplace_back(keys_from_seed<AccountKeys>(seed));
        k.created = std::chrono::sys_seconds{std::chrono::seconds{created}};
        if (rotated)
            k.rotated.emplace(std::chrono::seconds{*rotated});
        if (!rotated)
            have_active = true;
        if (std::memcmp(k.mlkem768_pub.data(), pk_ml.data(), pk_ml.size()) != 0 ||
            std::memcmp(k.x25519_pub.data(), pk_x.data(), pk_x.size()) != 0) {
            log::warning(
                    cat,
                    "device_account_keys row with id={} ignored: row contains invalid precomputed "
                    "pubkeys",
                    id);
            keys.pop_back();
        }
    }

    tx.commit();

    if (!key_indicator && !have_active) {
        log::info(cat, "No currently active account keys; generating a new one");
        rotate_account_keys();
        return active_account_keys();
    }

    return keys;
}

void Devices::_prune_account_keys() {
    conn().prepared_exec(
            "DELETE FROM device_account_keys WHERE rotated < ?",
            epoch_seconds(clock_now_s() - ACCOUNT_KEY_RETENTION));
}

std::vector<Devices::AccountKeyInfo> Devices::account_keys() {
    auto c = conn();
    SQLite::Transaction tx{c.sql};
    _prune_account_keys();

    std::vector<AccountKeyInfo> keys;
    for (auto [created, rotated, published, pk_ml, pk_x] : c.prepared_results<
                                                           int64_t,
                                                           std::optional<int64_t>,
                                                           int,
                                                           sqlite::blobn<mlkem768::PUBLICKEYBYTES>,
                                                           sqlite::blobn<32>>(
                 "SELECT created, rotated, published, pubkey_mlkem768, pubkey_x25519"
                 " FROM device_account_keys"
                 " ORDER BY rotated DESC NULLS FIRST, created DESC")) {
        auto& k = keys.emplace_back();
        std::memcpy(k.x25519_pub.data(), pk_x.data(), pk_x.size());
        std::memcpy(k.mlkem768_pub.data(), pk_ml.data(), pk_ml.size());
        k.created = std::chrono::sys_seconds{std::chrono::seconds{created}};
        if (rotated) {
            k.rotated.emplace(std::chrono::seconds{*rotated});
            k.retained_until = *k.rotated + std::chrono::duration_cast<std::chrono::seconds>(
                                                    ACCOUNT_KEY_RETENTION);
        }
        k.published = published != 0;
    }
    tx.commit();
    return keys;
}

namespace {

    // Builds a device::Info from the fields of a devices table row (excluding the row id, changes,
    // and kicked_timestamp columns, which are not part of device::Info).
    device::Info fill_device_info(
            std::span<const std::byte, device::ID_SIZE> devid,
            int state,
            int seqno,
            int64_t timestamp,
            std::string type,
            std::string desc,
            int64_t ver,
            const sqlite::blobn<mlkem768::PUBLICKEYBYTES>& pk_ml,
            const sqlite::blobn<32>& pk_x) {
        device::Info info;
        std::memcpy(info.id.data(), devid.data(), info.id.size());
        info.seqno = seqno;
        info.timestamp = std::chrono::sys_seconds{std::chrono::seconds{timestamp}};
        info.type = device::type_from_encoded(type);
        if (info.type == device::Type::Unknown)
            info.other_device = std::move(type);
        info.description = std::move(desc);
        info.state = static_cast<device::State>(state);
        info.version[2] = ver % 1000;
        info.version[1] = ver / 1000 % 1000;
        info.version[0] = ver / 1000000;
        std::memcpy(info.pk_x25519.data(), pk_x.data(), info.pk_x25519.size());
        std::memcpy(info.pk_mlkem768.data(), pk_ml.data(), info.pk_mlkem768.size());
        return info;
    }

    void load_device_extras(sqlite::Connection& c, int64_t row_id, device::Info& info) {
        for (auto [key, value] : c.prepared_results<std::string, sqlite::blob>(
                     "SELECT key, bt_value FROM device_unknown WHERE device = ? ORDER BY key",
                     row_id)) {
            try {
                info.extra[key] = oxenc::bt_deserialize<bt_value>(value);
            } catch (const std::exception& e) {
                log::warning(cat, "Failed to deserialize extra device data: {}", e.what());
            }
        }
    }

    // Upserts a device into the devices table and updates device_unknown extras.  Returns the row
    // id if the record was applied, nullopt if the guard rejected it as not newer.  info.id must be
    // set.
    //
    // The guard is `(state, seqno)` as a row value, not the seqno alone.  A state change is
    // invisible to the seqno -- state never goes on the wire, and is inferred from which message
    // the record arrived in -- so a seqno-only guard discards exactly the transitions it is there
    // to decide: an applicant is stored Pending at seqno 1, the accepting device pushes the
    // identical record as Registered at seqno 1, and `1 > 1` rejects it, leaving every device
    // Pending forever.
    //
    // Ranking the states makes the comparison decide both questions at once, and subsumes the
    // special cases: equal rank falls back to the seqno, an acceptance outranks a newer link
    // request, and a kick outranks everything so its tombstone -- which carries no seqno at all --
    // no longer needs an ungated update of its own.
    std::optional<int64_t> upsert_device_info(sqlite::Connection& c, const device::Info& info) {
        auto ver = info.version[0] * 1000000 + info.version[1] * 1000 + info.version[2];
        auto dev_id = c.prepared_maybe_get<int64_t>(
                R"(INSERT INTO devices
                    (unique_id, state, seqno, timestamp, device_type, description, version,
                     pubkey_mlkem768, pubkey_x25519, digest)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(unique_id) DO UPDATE SET
                       state = excluded.state,
                       seqno = excluded.seqno,
                       timestamp = excluded.timestamp,
                       device_type = excluded.device_type,
                       description = excluded.description,
                       version = excluded.version,
                       pubkey_mlkem768 = excluded.pubkey_mlkem768,
                       pubkey_x25519 = excluded.pubkey_x25519,
                       digest = excluded.digest
                   WHERE (excluded.state, excluded.seqno, excluded.digest) > (state, seqno, digest)
                   RETURNING id)",
                info.id,
                static_cast<int>(info.state),
                info.seqno,
                info.timestamp.time_since_epoch().count(),
                info.encoded_type(),
                info.description,
                ver,
                info.pk_mlkem768,
                info.pk_x25519,
                info.digest);

        if (!dev_id)
            return std::nullopt;

        c.prepared_exec("DELETE FROM device_unknown WHERE device = ?", *dev_id);
        for (const auto& [key, val] : info.extra) {
            auto encoded = std::visit([](const auto& v) { return oxenc::bt_serialize(v); }, val);
            c.prepared_exec(
                    "INSERT INTO device_unknown (device, key, bt_value) VALUES (?, ?, ?)",
                    *dev_id,
                    key,
                    to_span<std::byte>(encoded));
        }

        return dev_id;
    }

}  // namespace

device::map Devices::devices(
        bool include_registered,
        bool include_pending,
        bool include_unregistered,
        std::span<const std::byte> only_device) {

    // Encode included states as a bitmask, one bit per State value, so the query string is stable
    // regardless of which states are selected.
    //
    // `include_unregistered` covers Left and Kicked as well as Unregistered: they were one state
    // until the merge rules needed them apart, and a caller asking for devices that are not in the
    // group means all three.  Separating them here is a caller-visible change worth making on its
    // own.
    int state_mask = (include_registered ? 1 << static_cast<int>(device::State::Registered) : 0) |
                     (include_pending ? 1 << static_cast<int>(device::State::Pending) : 0) |
                     (include_unregistered ? (1 << static_cast<int>(device::State::Unregistered)) |
                                                     (1 << static_cast<int>(device::State::Left)) |
                                                     (1 << static_cast<int>(device::State::Kicked))
                                           : 0);
    if (state_mask == 0)
        return {};

    auto c = conn();
    SQLite::Transaction tx{c.sql};
    device::map devs;

    std::string query =
            "SELECT id, unique_id, state, seqno, timestamp, device_type, description,"
            "       version, pubkey_mlkem768, pubkey_x25519, kicked_timestamp"
            " FROM devices WHERE ((1 << state) & ?) != 0";
    if (!only_device.empty())
        query += " AND unique_id = ?";
    query += " ORDER BY unique_id";

    auto st = c.prepared_st(query);
    if (only_device.empty())
        bind_oneshot(st, state_mask);
    else
        bind_oneshot(st, state_mask, only_device);

    for (auto [id, devid, state, seqno, timestamp, type, desc, ver, pk_ml, pk_x, kicked] :
         sqlite::IterableStatementWrapper<
                 int64_t,
                 sqlite::blob_guts<device::Id>,
                 int,
                 int,
                 int64_t,
                 std::string,
                 std::string,
                 int64_t,
                 sqlite::blobn<mlkem768::PUBLICKEYBYTES>,
                 sqlite::blobn<32>,
                 std::optional<int64_t>>{std::move(st)}) {
        auto& info = devs[devid];
        info = fill_device_info(
                devid, state, seqno, timestamp, std::move(type), std::move(desc), ver, pk_ml, pk_x);
        if (kicked)
            info.kicked.emplace(std::chrono::seconds{*kicked});
        load_device_extras(c, id, info);
    }

    return devs;
}

void Devices::device_info(result_function<std::pair<device::Info, bool>> cb) {
    async([this] { return _device_info(); }, std::move(cb));
}

std::pair<device::Info, bool> Devices::device_info(await_t) {
    return jq().call_get([this] { return _device_info(); });
}

bool device::Info::same_user_fields(const Info& other) const {
    auto fields = [](const Info& i) {
        return std::tie(i.type, i.other_device, i.description, i.version, i.extra);
    };
    return fields(*this) == fields(other);
}

void Devices::update_info(device::Info info, result_function<> cb) {
    async([this, info = std::move(info)]() mutable { _update_info(std::move(info)); },
          std::move(cb));
}

void Devices::update_info(const device::Info& info, await_t) {
    jq().call_get([this, &info] { _update_info(info); });
}

namespace {

    // A message's per-device lists -- recipients, and the `kicked` list -- are padded to whole
    // buckets of this many entries, and its payload is sized by the same buckets, so that what an
    // outsider can measure says only which bucket a count falls in.
    constexpr size_t DEVICES_PER_BUCKET = 4;

    constexpr size_t whole_buckets(size_t n) {
        return (n + DEVICES_PER_BUCKET - 1) / DEVICES_PER_BUCKET * DEVICES_PER_BUCKET;
    }

    // The most removal markers a message for a group of `live` devices carries: a bucket's worth,
    // which keeps removal history the same share of the payload whatever the group's size.
    constexpr size_t removal_marker_cap(size_t live) {
        return whole_buckets(live);
    }

    // Plain-old-data representation of a single account key seed entry as read from or written to
    // the "K" list in the device group plaintext payload.
    struct AccountKeySeed {
        cleared_b32 seed;
        int64_t created;
        std::optional<int64_t> rotated;
    };

    struct GroupPayload {
        device::map devices;
        std::vector<AccountKeySeed> account_keys;
    };

    // Called while building a bt dict to pull out any unknown intermediate keys immediately before
    // appending a new one.  E.g. call `write_extra(out, "a", it, end)` to write out any keys from
    // `it` that precede "a".  `it` is mutated, and left at the first value > "a", ready for the
    // next call. The iterator range must be sorted (such as a bt_dict, or a std::map<std::string,
    // T>, but not an unordered_map).
    template <std::forward_iterator It, std::sentinel_for<It> End>
    void write_extras(bt_dict_producer& out, std::string_view until, It& it, End end) {
        for (; it != end; ++it) {
            auto& [k, v] = *it;
            if (auto comp = k <=> until; comp >= 0) {
                if (comp == 0)
                    // We found an exact match, which probably means we upgraded and learned what
                    // the key meant.  We probably shouldn't get here at all, but just in case skip
                    // it so we don't break the bt_dict.
                    ++it;
                return;
            }
            out.append_bt(k, v);
        }
    }

    // Combines a call to write_extras + out.append for appending simple bt dict keys with scalar
    // values.
    template <typename T, std::forward_iterator It, std::sentinel_for<It> End>
    void write_next(
            oxenc::bt_dict_producer& out, std::string_view key, const T& value, It& it, End end) {
        write_extras(out, key, it, end);
        out.append(key, value);
    }

    // What a device describes itself by -- its description, type and version, and whatever later
    // versions add (the rest of `info.extra`, from `xit` on) -- which is the tail of its record,
    // and the whole of this device's own copy of what it publishes (see `own_info_key`).
    void encode_described(
            oxenc::bt_dict_producer& devout,
            const device::Info& info,
            oxenc::bt_dict::const_iterator& xit,
            oxenc::bt_dict::const_iterator xend) {
        write_next(devout, "d", info.description, xit, xend);
        write_extras(devout, "t", xit, xend);
        if (auto t = info.encoded_type(); !t.empty())
            devout.append("t", t);
        auto ver = info.version[0] * 1000000 + std::clamp(info.version[1], 0, 999) * 1000 +
                   std::clamp(info.version[2], 0, 999);
        write_extras(devout, "v", xit, xend);
        if (ver != 0)
            devout.append("v", ver);
        for (; xit != xend; ++xit)
            devout.append_bt(xit->first, xit->second);
    }

    // Encodes the fields of a device::Info into an already-opened bt_dict_producer (passed as
    // rvalue to allow callers to pass sub-producers directly from append_dict()).
    void encode_device_info(oxenc::bt_dict_producer&& devout, const device::Info& info) {
        auto xit = info.extra.cbegin();
        auto xend = info.extra.cend();
        write_next(devout, "#", info.seqno, xit, xend);
        write_next(devout, "@", info.timestamp.time_since_epoch().count(), xit, xend);
        write_next(devout, "M", info.pk_mlkem768, xit, xend);
        write_next(devout, "X", info.pk_x25519, xit, xend);
        encode_described(devout, info, xit, xend);
    }

    bool tombstoned(const device::Info& info) {
        return info.state == device::State::Kicked || info.state == device::State::Left;
    }

    // What a message says about each device, in id order: every live record, and the most recent
    // removals and departures that are newer than REMOVAL_MARKER_MAX_AGE, at most
    // `removal_marker_cap` of them -- see "Which removals a message carries".  Pending and
    // unregistered devices are in no group, so there is nothing to say about them.
    //
    // Only the message is pruned, never the table: a local row costs nothing, and forgetting one
    // would lower its rank and let a stale message bring the device back.
    std::vector<const device::Info*> carried_records(
            const device::map& devices, std::chrono::sys_seconds now) {
        std::vector<const device::Info*> out, markers;
        for (const auto& [id, info] : devices) {
            if (info.state == device::State::Registered)
                out.push_back(&info);
            else if (tombstoned(info) && *info.kicked > now - Devices::REMOVAL_MARKER_MAX_AGE)
                markers.push_back(&info);
        }

        // Stable, so that a tie at the cut is settled by id, as the map has them.
        std::ranges::stable_sort(
                markers, std::ranges::greater{}, [](const device::Info* i) { return *i->kicked; });
        if (auto cap = removal_marker_cap(out.size()); markers.size() > cap)
            markers.resize(cap);

        out.insert(out.end(), markers.begin(), markers.end());
        std::ranges::sort(
                out, {}, [](const device::Info* i) -> const device::Id& { return i->id; });
        return out;
    }

    // `records` in id order, as `carried_records` gives them.
    std::string encode_group_payload(
            std::span<const device::Info* const> records,
            std::span<const AccountKeySeed> acc_keys) {
        oxenc::bt_dict_producer out;

        {
            auto devs = out.append_dict("D");
            for (const auto* info : records) {
                std::string_view id_sv{
                        reinterpret_cast<const char*>(info->id.data()), info->id.size()};

                // A tombstone is how every other device learns that a device is gone, since a
                // record merely absent from a message means "unchanged" rather than "removed".
                if (tombstoned(*info))
                    devs.append_dict(id_sv).append(
                            info->state == device::State::Left ? "l" : "r",
                            info->kicked->time_since_epoch().count());
                else
                    encode_device_info(devs.append_dict(id_sv), *info);
            }
        }  // "D" dict closed here

        if (!acc_keys.empty()) {
            auto kl = out.append_list("K");
            for (const auto& k : acc_keys) {
                auto e = kl.append_dict();
                e.append("c", k.created);
                if (k.rotated)
                    e.append("r", *k.rotated);
                e.append("s", k.seed);
            }
        }

        return std::move(out).str();
    }

    // The signed request: {"I": device id, "i": info dict, "~": signature by the account key}.  The
    // signature is what stops a request being forged by anyone who merely knows the group's link
    // key, which is published.
    std::string encode_link_request_plaintext(
            std::span<const std::byte, device::ID_SIZE> device_id,
            const device::Info& info,
            std::span<const std::byte, 64> ed25519_secret) {
        oxenc::bt_dict_producer out;
        out.append("I", device_id);
        encode_device_info(out.append_dict("i"), info);
        out.append_signature("~", [&](std::span<const std::byte> body) {
            return ed25519::sign(ed25519_secret, body);
        });
        return std::move(out).str();
    }

    // Stores the current btdc key/value in `extra`; the value is consumed (i.e. the consumer
    // advances to the next key).
    void consume_extra(oxenc::bt_dict_consumer& btdc, oxenc::bt_dict& extra) {
        auto& x = extra[std::string{btdc.key()}];
        if (btdc.is_string())
            x = btdc.consume_string();
        else if (btdc.is_unsigned_integer())
            x = btdc.consume_integer<uint64_t>();
        else if (btdc.is_integer())
            x = btdc.consume_integer<int64_t>();
        else if (btdc.is_dict())
            x = btdc.consume_dict();
        else
            x = btdc.consume_list();
    }

    // Consumes and stores any unknown extra fields from `btdc` up to (but not including) `key` into
    // `extras`
    void read_extras(oxenc::bt_dict_consumer& btdc, std::string_view key, oxenc::bt_dict& extra) {
        while (!btdc.is_finished() && btdc.key() < key)
            consume_extra(btdc, extra);
    }

    // The inverse of `encode_described`.
    void decode_described(device::Info& info, oxenc::bt_dict_consumer& dev) {
        read_extras(dev, "d", info.extra);
        // A record from a newer or broken device can carry more than the protocol allows.
        info.description = utf8_truncate(
                std::string{dev.maybe<std::string_view>("d").value_or(""sv)},
                device::DESCRIPTION_MAX);

        read_extras(dev, "t", info.extra);
        auto type = dev.maybe<std::string_view>("t").value_or(""sv);
        info.type = device::type_from_encoded(type);
        info.other_device = info.type == device::Type::Unknown ? std::string{type} : std::string{};

        read_extras(dev, "v", info.extra);
        auto ver = dev.maybe<int64_t>("v").value_or(0);
        info.version[0] = ver / 1000000;
        info.version[1] = ver / 1000 % 1000;
        info.version[2] = ver % 1000;

        while (!dev.is_finished())
            consume_extra(dev, info.extra);
    }

    void decode_one(device::Info& info, oxenc::bt_dict_consumer dev, device::State state) {
        info.state = state;
        read_extras(dev, "#", info.extra);
        info.seqno = dev.require<int64_t>("#");

        read_extras(dev, "@", info.extra);
        info.timestamp = std::chrono::sys_seconds{std::chrono::seconds{dev.require<int64_t>("@")}};

        read_extras(dev, "M", info.extra);
        auto M = dev.require_span<std::byte, mlkem768::PUBLICKEYBYTES>("M");
        std::memcpy(info.pk_mlkem768.data(), M.data(), M.size());

        read_extras(dev, "X", info.extra);
        auto X = dev.require_span<std::byte, 32>("X");
        std::memcpy(info.pk_x25519.data(), X.data(), X.size());

        decode_described(info, dev);
    }

    // The device record a stored link request asks to have admitted.  Already verified when the
    // request was received.
    device::Info requested_record(
            std::span<const std::byte, device::ID_SIZE> id, std::span<const std::byte> encoded) {
        device::Info info;
        std::ranges::copy(id, info.id.begin());
        decode_one(info, oxenc::bt_dict_consumer{encoded}, device::State::Pending);
        info.digest = hash::blake2b<8>(encoded);
        return info;
    }

    // The digest a device record has as a group message carries it: the last term of the merge
    // comparison, so a record we change ourselves has to carry the digest every other device will
    // compute for it.
    std::array<std::byte, 8> record_digest(const device::Info& info) {
        oxenc::bt_dict_producer out;
        encode_device_info(std::move(out), info);
        return hash::blake2b<8>(std::move(out).str());
    }

    // The state and time a tombstone carries -- {"r": when} for a device removed, {"l": when} for
    // one that left -- or nullopt for a live record.  Told apart by the seqno, which every record
    // carries and no tombstone does; anything else in a tombstone is for a later version, and
    // ignored.  Either way the id is spent, and the device must take a new one to come back.
    std::optional<std::pair<device::State, std::chrono::sys_seconds>> decode_tombstone(
            std::string_view raw) {
        oxenc::bt_dict_consumer in{raw};
        if (in.skip_until("#"))
            return std::nullopt;
        auto left = in.maybe<int64_t>("l");
        auto removed = in.maybe<int64_t>("r");
        if (left.has_value() == removed.has_value())
            throw std::runtime_error{
                    "Invalid encoded device data: a tombstone needs exactly one of 'l' and 'r'"};
        auto t = left ? *left : *removed;
        if (t <= 0)
            throw std::runtime_error{"Invalid encoded device data: invalid tombstone timestamp"};
        return std::pair{
                left ? device::State::Left : device::State::Kicked,
                std::chrono::sys_seconds{std::chrono::seconds{t}}};
    }

    // Decodes the plaintext bt-encoded device group payload.  The returned device map will include
    // both full device records and tombstoned devices: the latter have a mostly default-constructed
    // Info where only id, state (Kicked or Left), and kicked are set.
    GroupPayload decode_group_payload(std::span<const std::byte> data) {
        GroupPayload result;

        oxenc::bt_dict_consumer in{data};
        auto devs = in.require<bt_dict_consumer>("D");

        while (!devs.is_finished()) {
            auto in_id = devs.key();
            if (in_id.size() != device::ID_SIZE)
                throw std::runtime_error{
                        "Invalid encoded device data: unexpected {}-byte key in device dict (expected {})"_format(
                                in_id.size(), device::ID_SIZE)};

            device::Id id;
            std::memcpy(id.data(), in_id.data(), id.size());
            auto [it, ins] = result.devices.try_emplace(id);
            if (!ins)
                throw std::runtime_error{"Invalid encoded device data: duplicate device ids"};

            auto& info = it->second;
            info.id = id;

            // The encoded record itself, rather than what we would make of it again: taking the
            // view costs nothing here, and re-encoding to hash would.
            auto raw = devs.consume_dict_data();
            if (auto gone = decode_tombstone(raw)) {
                std::tie(info.state, info.kicked) = *gone;
            } else {
                decode_one(info, oxenc::bt_dict_consumer{raw}, device::State::Registered);
                info.digest = hash::blake2b<8>(raw);
            }
        }

        auto kl = in.require<bt_list_consumer>("K");
        while (!kl.is_finished()) {
            auto& k = result.account_keys.emplace_back();
            auto e = kl.consume_dict_consumer();
            k.created = e.require<int64_t>("c");
            k.rotated = e.maybe<int64_t>("r");
            auto s = e.require_span<std::byte, 32>("s");
            std::memcpy(k.seed.data(), s.data(), 32);
        }

        return result;
    }

    constexpr auto PERS_DEV_NONCE = "SessionDevDNonce"_b2b_pers;
    constexpr auto PERS_KEY_NONCE = "SessionDevKNonce"_b2b_pers;
    constexpr auto PERS_KEY_KEY = "SessionDevKeyKey"_b2b_pers;
    constexpr auto PERS_KEY_KEY_IDX = "SessionDevKeyIdx"_b2b_pers;
    constexpr auto PERS_ACC_KEY_ROT = "SessionAccKeyRot"_b2b_pers;
    constexpr auto PERS_KICKED = "SessionDevKicked"_b2b_pers;
    constexpr auto PERS_GROUP_ID_KEY = "SessionDvGrpID_K"_b2b_pers;
    constexpr auto PERS_GROUP_ID_NONCE = "SessionDvGrpID_N"_b2b_pers;
    constexpr auto PERS_GROUP_SAS = "SessionDvGrp_SAS"_b2b_pers;
    constexpr auto PERS_LINK = "SessionDvGrpLink"_b2b_pers;
    constexpr auto PERS_LINK_KISS = "SessionDvGrpKISS"_b2b_pers;

    // A link request's key and nonce, from the secret its sender's ephemeral key `E` shares with
    // the group's link key `X`.
    struct LinkKey {
        cleared_b32 key;
        std::array<std::byte, encryption::XCHACHA20_NONCEBYTES> nonce;
    };
    LinkKey link_request_key(
            std::span<const std::byte, 32> shared,
            std::span<const std::byte, 32> E,
            std::span<const std::byte, 32> X) {
        cleared_array<std::byte, 56> kn;
        hash::blake2b_pers(kn, PERS_LINK, shared, E, X);
        LinkKey out;
        std::ranges::copy(std::span{kn}.first<32>(), out.key.begin());
        std::ranges::copy(std::span{kn}.last<24>(), out.nonce.begin());
        return out;
    }

    // What a link request's key indicator is masked with: the secret `E` shares with the account's
    // long-term key `S`, so that only a seed holder can tell which group a request is for.
    std::array<std::byte, 2> link_request_kiss(
            std::span<const std::byte, 32> shared,
            std::span<const std::byte, 32> E,
            std::span<const std::byte, 32> S) {
        std::array<std::byte, 2> out;
        hash::blake2b_key_pers(out, shared, PERS_LINK_KISS, E, S);
        return out;
    }

    // Encrypts or decrypts group identifiers for a message's outer `@` (XChaCha20 being its own
    // inverse): readable by any holder of the account seed, and different in every message to
    // anyone else, the nonce coming from that message's A.  Several are one stream, so the first of
    // them is encrypted exactly as a lone one would be.
    void crypt_group_ids(
            std::span<std::byte> out,
            std::span<const std::byte> in,
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> seed) {
        cleared_b32 key;
        hash::blake2b_pers(key, PERS_GROUP_ID_KEY, seed);
        std::array<std::byte, encryption::XCHACHA20_NONCEBYTES> nonce;
        hash::blake2b_pers(nonce, PERS_GROUP_ID_NONCE, A);
        encryption::xchacha20_xor(out, in, nonce, key);
    }

    std::array<std::byte, 8> crypt_group_id(
            std::span<const std::byte, 8> in,
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> seed) {
        std::array<std::byte, 8> out;
        crypt_group_ids(out, in, A, seed);
        return out;
    }

    // A removed device's entry in a message's `kicked` list: computable only with the account seed,
    // and different in every message, being keyed by that message's ephemeral A.
    std::array<std::byte, 16> kicked_entry(
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> seed,
            std::span<const std::byte, device::ID_SIZE> device_id) {
        std::array<std::byte, 16> out;
        hash::blake2b_key_pers(out, A, PERS_KICKED, seed, device_id);
        return out;
    }

    // Device group payloads are null-padded to a multiple of this before encryption so that the
    // encrypted size reveals only which bucket the payload falls in, not what it contains.  A
    // bucket is four devices at a budget of 1600 bytes each, a deliberate overestimate of a
    // ~1325-byte record, with the remainder of a bucket left for removal tombstones.
    constexpr size_t DEVICE_PAYLOAD_PADDING = DEVICES_PER_BUCKET * 1600;

    // Added before the buckets: the account key list is carried by every payload whatever the
    // device count, and is bounded by the rotation period and retention window -- at most 33
    // entries of ~70 bytes.  Without a fixed allowance for it, it would consume most of the first
    // bucket and the bucketing would stop meaning what it is supposed to mean.
    constexpr size_t ACCOUNT_KEYS_ALLOWANCE = 2300;

    constexpr int bt_bytes_encoded(int x) {
        int sz = 1 + x;

        do {
            ++sz;
        } while (x /= 10);

        return sz;
    }

    static_assert(bt_bytes_encoded(0) == 2);      // "0:"
    static_assert(bt_bytes_encoded(9) == 11);     // "9:…"
    static_assert(bt_bytes_encoded(10) == 13);    // "10:…"
    static_assert(bt_bytes_encoded(99) == 102);   // "99:…"
    static_assert(bt_bytes_encoded(100) == 104);  // "100:…"

    // The encoded size of a non-negative integer.
    constexpr int bt_int_encoded(int64_t x) {
        int sz = 2;

        do {
            ++sz;
        } while (x /= 10);

        return sz;
    }

    static_assert(bt_int_encoded(0) == 3);               // "i0e"
    static_assert(bt_int_encoded(1777777777123) == 15);  // "i1777777777123e"

    // When a group message's author wrote it, by its own clock: the outer "t", which the account
    // signature covers, as it does not the swarm's timestamp.
    sys_ms group_message_time(std::span<const std::byte> message) {
        oxenc::bt_dict_consumer in{message};
        in.require<std::string_view>("");
        return from_epoch_ms(in.require<int64_t>("t"));
    }

}  // namespace

std::chrono::sys_time<std::chrono::minutes> device::GroupId::created() const {
    return std::chrono::sys_time<std::chrono::minutes>{
            std::chrono::minutes{oxenc::load_little_to_host<uint32_t>(value.data())}};
}

Sas device::GroupId::sas() const {
    std::array<std::byte, 16> seed;
    hash::blake2b_pers(seed, PERS_GROUP_SAS, value);
    return sas_from_seed(seed);
}

device::Info Devices::_described() {
    device::Info info{};
    if (auto blob = core.globals.get_blob(own_info_key)) {
        oxenc::bt_dict_consumer in{std::span<const std::byte>{*blob}};
        decode_described(info, in);
    }
    return info;
}

std::optional<device::Info> Devices::_held_record() {
    auto held = devices(true, true, true, self_id);
    if (held.empty())
        return std::nullopt;
    return std::move(held.begin()->second);
}

device::Info Devices::_own_record() {
    auto own = _described();
    own.id = self_id;
    auto keys = active_device_keys();
    own.pk_x25519 = keys.front().x25519_pub;
    own.pk_mlkem768 = keys.front().mlkem768_pub;

    auto held = _held_record();
    own.state = held ? held->state : device::State::Unregistered;
    own.kicked = held ? held->kicked : std::nullopt;

    // Seqno 0 holds nothing: a group just established, whose swarm has no record of ours yet.
    if (held && held->seqno > 0 && held->same_user_fields(own) &&
        held->pk_x25519 == own.pk_x25519 && held->pk_mlkem768 == own.pk_mlkem768)
        return std::move(*held);

    own.seqno = (held ? held->seqno : 0) + 1;
    own.timestamp = clock_now_s();
    own.digest = record_digest(own);
    return own;
}

std::pair<device::Info, bool> Devices::_device_info() {
    assert(on_loop());
    auto own = _own_record();
    bool registered = own.state == device::State::Registered;
    return {std::move(own), registered};
}

void Devices::_update_info(device::Info info) {
    assert(on_loop());
    // Reading the master copy back cuts it too, but cutting here keeps the stored copy itself to
    // what is published, and makes a change only past the cap no write at all.
    info.description = utf8_truncate(std::move(info.description), device::DESCRIPTION_MAX);
    if (_described().same_user_fields(info))
        return;

    oxenc::bt_dict_producer out;
    auto xit = info.extra.cbegin();
    encode_described(out, info, xit, info.extra.cend());
    auto encoded = std::move(out).str();
    core.globals.set(own_info_key, to_span<std::byte>(encoded));
    _push_soon();
}

std::optional<device::GroupId> Devices::_group_id() {
    device::GroupId id;
    if (core.globals.get_blob_to(group_id_key, id.value))
        return id;
    return std::nullopt;
}

void Devices::_set_group_id(const device::GroupId& id) {
    core.globals.set(group_id_key, std::span<const std::byte>{id.value});
}

void Devices::_verify_account_signature(oxenc::bt_dict_consumer& in, std::string_view what) {
    in.require_signature("~", [&](std::span<const std::byte> body, std::span<const std::byte> sig) {
        if (sig.size() != 64 ||
            !ed25519::verify(sig.first<64>(), core.globals.pubkey_ed25519(), body))
            throw std::runtime_error{"Invalid {}: signature verification failed"_format(what)};
    });
}

sys_ms Devices::_signed_time(oxenc::bt_dict_consumer& in, std::string_view what) {
    auto t = from_epoch_ms(in.require<int64_t>("t"));
    _verify_account_signature(in, what);
    if (auto ahead = t - clock_now_ms(); ahead > GROUP_MESSAGE_MAX_AHEAD)
        throw std::runtime_error{"Ignoring {} dated {}s ahead of this device's clock"_format(
                what, std::chrono::floor<std::chrono::seconds>(ahead).count())};
    return t;
}

std::optional<sys_ms> Devices::_dissolved_at(const device::GroupId& group) {
    if (auto at = conn().prepared_maybe_get<int64_t>(
                "SELECT dissolved_at FROM device_dissolved_groups WHERE group_id = ?",
                std::span<const std::byte>{group.value}))
        return from_epoch_ms(*at);
    return std::nullopt;
}

device::GroupId Devices::_group_of(std::span<const std::byte> message) {
    oxenc::bt_dict_consumer in{message};
    in.require<std::string_view>("");
    auto encrypted = in.require_span<std::byte, 8>("@");
    auto A = in.require_span<std::byte, 32>("A");
    auto seed = core.globals.account_seed();
    return device::GroupId{crypt_group_id(encrypted, A, seed.seed())};
}

std::vector<std::byte> Devices::encrypt_device_data(const device::map& devices) {
    auto records = carried_records(devices, clock_now_s());

    // Fetch account key seeds for inclusion in the payload.
    std::vector<AccountKeySeed> acc_keys;
    for (auto [seed, created, rotated] :
         conn().prepared_results<sqlite::blobn<32>, int64_t, std::optional<int64_t>>(
                 "SELECT seed, created, rotated FROM device_account_keys"
                 " ORDER BY rotated DESC NULLS FIRST, created DESC")) {
        auto& k = acc_keys.emplace_back();
        std::memcpy(k.seed.data(), seed.data(), 32);
        k.created = created;
        k.rotated = rotated;
    }

    // The current account key's X25519 half, published outside the payload so that a device asking
    // to join can encrypt its request to the group: only members hold the secret half.
    if (acc_keys.empty() || acc_keys.front().rotated)
        throw std::logic_error{"Cannot build a device group message without a current account key"};
    auto link_x25519 = keys_from_seed<AccountKeys>(acc_keys.front().seed).x25519_pub;

    return _encrypt_group_payload(records, link_x25519, encode_group_payload(records, acc_keys));
}

std::vector<std::byte> Devices::_encrypt_group_payload(
        std::span<const device::Info* const> records,
        const std::array<std::byte, 32>& link_x25519,
        std::string payload) {
    cleared_b32 a;
    random::fill(a);

    auto A = x25519::scalarmult_base(a);

    // Who can read this, which is not the same as who appears in it.  A kicked device is written
    // into the payload -- a tombstone carrying when it was kicked is how every other device learns
    // it is gone -- but must not be given a key, which is the entire point of removing it.  A
    // pending device is in neither: it is not in the group until someone accepts it.
    std::vector<const device::Info*> recipients;
    for (const auto* info : records)
        if (info->state == device::State::Registered)
            recipients.push_back(info);

    auto group_id = _group_id();
    if (!group_id)
        throw std::logic_error{"Cannot build a device group message outside a group"};
    std::array<std::byte, 8> group_id_enc;

    // Removals among the tombstones carried, announced to the devices removed, which have no key to
    // read them from the payload.  Departures are left out: the device that left knows, and would
    // read its own entry as a removal.  Shuffled into whole buckets, like the recipient lists.
    std::vector<std::byte> kicked_raw;
    {
        auto seed = core.globals.account_seed();
        group_id_enc = crypt_group_id(group_id->value, A, seed.seed());

        std::vector<const device::Id*> removed;
        for (const auto* info : records)
            if (info->state == device::State::Kicked)
                removed.push_back(&info->id);

        std::vector<size_t> slots(whole_buckets(removed.size()));
        std::iota(slots.begin(), slots.end(), 0);
        std::ranges::shuffle(slots, csrng);

        kicked_raw.resize(16 * slots.size());
        random::fill(kicked_raw);
        for (size_t i = 0; i < removed.size(); i++)
            std::ranges::copy(
                    kicked_entry(A, seed.seed(), *removed[i]), kicked_raw.begin() + 16 * slots[i]);
    }

    int padded_count = whole_buckets(recipients.size());

    auto indices = std::views::iota(0, padded_count);

    // We randomize the positions of devices (and padding) in the list of keys, so build a random
    // mapping first so that we place everything directly into its final position through it:
    std::vector<int> pos_map{indices.begin(), indices.end()};
    std::ranges::shuffle(pos_map, csrng);

    // Holds MLKEM ciphertexts:
    std::vector<std::byte> ciphertext_raw;
    ciphertext_raw.resize(mlkem768::CIPHERTEXTBYTES * padded_count);
    // Holds per-device-encrypted copies of the base key, each prefixed with a 2-byte key indicator
    // hash:
    std::vector<std::byte> enc_key_raw;
    enc_key_raw.resize((2 + 32) * padded_count);

    // Accessor for the relevant, position-mapped subspan of ciphertext_raw/enc_key_raw containing
    // the location of index i as a subspan of the raw vector:
    auto ciphertext = indices | std::views::transform([&](int i) {
                          return std::span<std::byte, mlkem768::CIPHERTEXTBYTES>{
                                  ciphertext_raw.data() + pos_map[i] * mlkem768::CIPHERTEXTBYTES,
                                  mlkem768::CIPHERTEXTBYTES};
                      });

    auto enc_indicator =
            indices | std::views::transform([&](int i) {
                return std::span<std::byte, 2>{enc_key_raw.data() + pos_map[i] * (2 + 32), 2};
            });

    auto enc_key =
            indices | std::views::transform([&](int i) {
                return std::span<std::byte, 32>{enc_key_raw.data() + pos_map[i] * (2 + 32) + 2, 32};
            });

    cleared_vector<std::byte> ml_ss_raw(mlkem768::SHAREDSECRETBYTES * recipients.size());

    // Dynamic ss subspan accessor of ml_ss_raw, but *doesn't* go through the pos_map (unlike the
    // above constructs), and only goes up to the actual number of devices, not the padded number
    // (because this is never transmitted, and so not shuffled or padded).
    auto ml_ss =
            std::views::iota(size_t{0}, recipients.size()) | std::views::transform([&](size_t i) {
                return std::span<std::byte, mlkem768::SHAREDSECRETBYTES>{
                        ml_ss_raw.data() + i * mlkem768::SHAREDSECRETBYTES,
                        mlkem768::SHAREDSECRETBYTES};
            });

    cleared_b32 rnd;
    int i = -1;
    for (const auto* info : recipients) {
        ++i;
        random::fill(rnd);
        mlkem768::encapsulate(ciphertext[i], ml_ss[i], info->pk_mlkem768, rnd);
    }
    // Fill padding entries with randomness.  `++i` first: the loop above leaves `i` on the last
    // real entry, and starting here would overwrite it with noise -- which nothing detects when
    // there is more than one recipient, because some other slot still decrypts.
    for (++i; i < padded_count; i++)
        random::fill(ciphertext[i]);

    std::array<std::byte, encryption::XCHACHA20_NONCEBYTES> nonce;
    hash::blake2b_key_pers(nonce, A, PERS_DEV_NONCE, ciphertext_raw);

    cleared_b32 key_base;
    random::fill(key_base);

    auto plaintext_devices = std::move(payload);
    // 2300 + 6400N: at least one bucket, so a payload smaller than the account key allowance still
    // pads up rather than down to nothing.
    auto buckets = std::max<size_t>(
            1,
            (plaintext_devices.size() - std::min(plaintext_devices.size(), ACCOUNT_KEYS_ALLOWANCE) +
             DEVICE_PAYLOAD_PADDING - 1) /
                    DEVICE_PAYLOAD_PADDING);
    plaintext_devices.resize(ACCOUNT_KEYS_ALLOWANCE + buckets * DEVICE_PAYLOAD_PADDING);

    std::vector<std::byte> enc_devices;
    enc_devices.resize(plaintext_devices.size() + encryption::XCHACHA20_ABYTES);
    encryption::xchacha20poly1305_encrypt(enc_devices, to_span(plaintext_devices), nonce, key_base);

    cleared_b32 ki;
    cleared_b32 aB;
    i = -1;
    for (const auto* info : recipients) {
        ++i;
        auto eind = enc_indicator[i];
        auto ekey = enc_key[i];
        auto ct = ciphertext[i];

        auto& B = info->pk_x25519;
        if (!x25519::scalarmult(aB, a, B)) {
            // This really shouldn't happen: we shouldn't have accepted an invalid pubkey in the
            // first place.
            log::error(
                    cat,
                    "X25519 scalarmult failed: device '{}' ({}) published an invalid X25519 "
                    "pubkey!",
                    oxenc::to_hex(info->id),
                    info->description);
            // Without a proper key, we can't properly encrypt for the device so we'll just have to
            // fill the entry with random and move on.
            random::fill(eind);
            random::fill(ekey);
            continue;
        }

        hash::blake2b_key_pers(nonce, A, PERS_KEY_NONCE, ct, enc_devices);
        hash::blake2b_pers(ki, PERS_KEY_KEY, aB, A, B, ml_ss[i], info->pk_mlkem768);

        static_assert(decltype(ekey)::extent == key_base.size());
        encryption::xchacha20_xor(ekey, key_base, nonce, ki);

        // Hash a bunch of stuff together as a checksum to let decryption skip most not-for-me
        // values.
        hash::blake2b_pers(eind, PERS_KEY_KEY_IDX, A, B, info->pk_mlkem768, ct, ekey);
    }
    // Fill padding entries with randomness; `++i` for the same reason as above.
    for (++i; i < padded_count; i++) {
        random::fill(enc_indicator[i]);
        random::fill(enc_key[i]);
    }

    // We're done: now we just need to encode everything together:
    auto t = epoch_ms(clock_now_ms());
    std::vector<std::byte> out;
    out.resize(
            2                                              // Outer "d" ... "e" delimiters
            + 5                                            // "0:" + "1:G" (message type indicator)
            + 3 + bt_bytes_encoded(group_id_enc.size())    // "1:@" + "8:...(enc group id)..."
            + 3 + bt_bytes_encoded(A.size())               // "1:A" + "32:...(A eph pk)..."
            + 3 + bt_bytes_encoded(ciphertext_raw.size())  // "1:C" + "NNNN:...(mlkem cts)..."
            + 3 + bt_bytes_encoded(enc_key_raw.size())     // "1:K" + "NNN:...(encrypted keys)..."
            + 3 + bt_bytes_encoded(link_x25519.size())     // "1:X" + "32:...(link x25519 pk)..."
            + 3 + bt_bytes_encoded(enc_devices.size())     // "1:d" + "MMMM:...(enc device info)..."
            +
            (kicked_raw.empty() ? 0 : 3 + bt_bytes_encoded(kicked_raw.size()))  // "1:k" + "NN:..."
            + 3 + bt_int_encoded(t)     // "1:t" + "i...(author's time)...e"
            + 3 + bt_bytes_encoded(64)  // "1:~" + "64:...(Ed25519 signature)..."
    );

    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};

    o.append("", "G");
    o.append("@", group_id_enc);
    o.append("A", A);
    o.append("C", ciphertext_raw);
    o.append("K", enc_key_raw);
    o.append("X", link_x25519);
    o.append("d", enc_devices);
    if (!kicked_raw.empty())
        o.append("k", kicked_raw);
    o.append("t", t);
    o.append_signature("~", [seed = core.globals.account_seed()](std::span<const std::byte> body) {
        return ed25519::sign(seed.ed25519_secret(), body);
    });

    assert(o.view().size() == out.size());  // Ensure we calculated exactly the right size above

    return out;
}

// Records a device as removed (?3 = Kicked) or departed (?3 = Left) at ?1, inserting a bare
// tombstone row if we hold no record of it.
//
// The insert half is what makes a removal durable for a device that joined after it: an update
// alone matches nothing, stores nothing, and leaves that device free to accept the removed one back
// into the group.  A tombstone needs no details to do its job -- rank alone settles the merge -- so
// the columns the schema requires are filled with zeroes and the seqno left at 0, which no record
// off the wire can be.
//
// Ranked like every other merge: Kicked outranks Left outranks any live record, and between two
// tombstones of one kind the later wins.  Every group message carries the group's recent
// tombstones, so most of these restate what is already held, and only a real change returns a row.
//
// Owes no broadcast: the message it came in is already in the swarm, and stays there until a push
// carrying it forward replaces it.  Relaying it would only have every member push at once.
static const std::string TOMBSTONE_SQL =
        "INSERT INTO devices"
        " (unique_id, state, seqno, timestamp, device_type, description, version,"
        "  pubkey_mlkem768, pubkey_x25519, kicked_timestamp)"
        " VALUES (?2, ?3, 0, ?1, '', '', 0, zeroblob(1184), zeroblob(32), ?1)"
        " ON CONFLICT(unique_id) DO UPDATE SET"
        "     state = excluded.state, kicked_timestamp = excluded.kicked_timestamp"
        "   WHERE (excluded.state, excluded.kicked_timestamp) > (state, kicked_timestamp)"
        " RETURNING id";

// A device registered by a group message was admitted somewhere, so the request that asked for it
// has been answered, whichever device answered it.
static const std::string ANSWER_REQUEST_SQL =
        "UPDATE device_link_requests SET status = {} WHERE device = ? AND status = {}"_format(
                static_cast<int>(device::LinkStatus::Accepted),
                static_cast<int>(device::LinkStatus::Pending));

// The same for a device already in the group, whose record changing says nothing on its own: it
// changes whenever the device updates its details or rotates its keys.  A request was answered if
// the record now carries the keys it asked for.
static void answer_replacements(
        sqlite::Connection& c,
        int64_t dev_id,
        std::span<const std::byte, device::ID_SIZE> id,
        const device::Info& record) {
    std::vector<int64_t> answered;
    for (auto [row, encoded] : c.prepared_results<int64_t, sqlite::blob>(
                 "SELECT id, info FROM device_link_requests"
                 " WHERE device = ? AND replaces = 1 AND status = {}"_format(
                         static_cast<int>(device::LinkStatus::Pending)),
                 dev_id)) {
        auto asked = requested_record(id, encoded);
        if (asked.pk_x25519 == record.pk_x25519 && asked.pk_mlkem768 == record.pk_mlkem768)
            answered.push_back(row);
    }
    for (auto row : answered)
        c.prepared_exec(
                "UPDATE device_link_requests SET status = ? WHERE id = ?",
                static_cast<int>(device::LinkStatus::Accepted),
                row);
}

// Restates a removal that an incoming message tried to undo, moving the tombstone to the front of
// the removed list and marking it for broadcast.
//
// Refusing the record locally is not enough: a device that never saw the removal -- offline at the
// time, or joined after messages stopped carrying the tombstone -- has no reason to refuse it, and
// would go on treating the device as a member and encrypting to it.  Nothing reconciles that
// afterwards, since a record absent from a message means "unchanged" rather than "removed", so the
// two devices would hold permanently different groups.  A tombstone propagates where a refusal
// does not.
//
// The timestamp is moved to now rather than left at the original removal, because retention keeps
// the most recently removed: a tombstone left to age could be evicted while the device it names is
// still trying to return, either by waiting out the window or by provoking enough other removals to
// displace it.
//
// Applies equally to a device that left: it holds the seed just the same.
static const std::string REASSERT_TOMBSTONE_SQL =
        "UPDATE devices SET kicked_timestamp = ?, broadcast_needed = broadcast_needed + 1"
        " WHERE unique_id = ?";

void Devices::receive_device_group_message(
        std::span<const std::byte> data, const std::string& hash, bool confirmed) {
    auto t = group_message_time(data);
    GroupPayload payload;
    try {
        auto raw = decrypt_device_data(std::as_bytes(data));
        payload = decode_group_payload(raw);
    } catch (const device::decryption_failed& e) {
        // Only our own group's messages say anything of us.  Another group's lists removals from
        // that group, which a device that once was in it would otherwise take as its own.
        if (_group_of(data) != _group_id()) {
            log::warning(cat, "Ignoring incoming device group message: {}", e.what());
            return;
        }

        auto verdict = _unreadable_verdict(data);
        if (verdict == device::Membership::Removed) {
            // When we learned of it, which is the nearest we can say: the removal time is in the
            // payload we can no longer read.  Only from a live state, so that every later message
            // still naming us leaves it where it is.
            //
            // Not held to the timing below: nothing written before our admission names our id,
            // which is new to every group we join, while a removal made just after a message we
            // read would otherwise go unnoticed until the group next pushed.
            if (conn().prepared_maybe_get<int64_t>(
                        "UPDATE devices SET state = ?, kicked_timestamp = ?"
                        " WHERE unique_id = ? AND state < ? RETURNING id",
                        static_cast<int>(device::State::Kicked),
                        epoch_seconds(clock_now_s()),
                        self_id,
                        static_cast<int>(device::State::Kicked))) {
                log::warning(cat, "This device has been removed from its device group");
                _devices_changed = true;
            }
            return;
        }

        // Every message from our group is encrypted to us while we are in it, so a newer one we
        // cannot read means the group has moved on without us.  Older ones say nothing: they are
        // from before we joined, or snapshots overtaken since -- see DISPLACEMENT_GRACE.
        auto read_at = core.globals.get_integer(read_at_key);
        if (read_at && t > from_epoch_ms(*read_at) + DISPLACEMENT_GRACE && _registered()) {
            if (verdict == device::Membership::Displaced) {
                core.globals.set(displaced_key, epoch_ms(t));
                log::warning(
                        cat, "Another device has taken this device's place in its device group");
            } else {
                if (auto dropped = core.globals.get_integer(dropped_key);
                    !dropped || epoch_ms(t) > *dropped)
                    core.globals.set(dropped_key, epoch_ms(t));
                log::warning(cat, "This device can no longer read its device group");
            }
            return;
        }
        log::warning(cat, "Ignoring incoming device group message: {}", e.what());
        return;
    }

    auto theirs = _group_of(data);
    auto ours = _group_id();

    // A member of the group merges whatever it can read of it.
    bool member =
            ours == theirs && conn().prepared_maybe_get<int>(
                                      "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                                      self_id,
                                      static_cast<int>(device::State::Registered));

    // Anything else is ours only as an admission on one of our own requests, which we make only
    // from outside a group.  Being able to read it shows only that some holder of the seed
    // encrypted it to us, so it admits us only once the user has confirmed the SAS of that very
    // request -- the one the approving device showed, identified by the record it admitted.
    std::optional<OwnRequest> accepted;
    if (!member) {
        auto self = payload.devices.find(self_id);
        if (self != payload.devices.end() && self->second.state == device::State::Registered)
            accepted = _own_request_admitted(theirs, self->second);
        if (!accepted) {
            log::warning(cat, "Not merging a readable device group message from another group");
            return;
        }
        // Held only for the request the user is looking at.  One they moved on from by asking
        // again is not what they will confirm; the newer request admits them instead.
        if (auto newest = _newest_request(); !newest || newest->row != accepted->row) {
            log::info(cat, "Admitted on a request the user has since replaced; ignoring");
            return;
        }
        if (!confirmed) {
            // The first stands: the user may already be comparing emoji against it, and a seed
            // holder could otherwise swap in an admission of its own beneath their confirmation.
            if (accepted->held) {
                if (conn().prepared_get<std::string>(
                            "SELECT admission_hash FROM device_own_requests WHERE id = ?",
                            accepted->row) != hash)
                    log::warning(
                            cat,
                            "Ignoring a second admission on a request already approved; keeping "
                            "the first");
                return;
            }
            conn().prepared_exec(
                    "UPDATE device_own_requests SET admission = ?, admission_hash = ? WHERE id = ?",
                    data,
                    hash,
                    accepted->row);
            log::info(
                    cat, "Admitted to a device group; holding it until the user confirms the SAS");
            return;
        }
    }
    bool admitting = accepted.has_value();

    // Asking is only ever from outside a group -- one removed or displaced from its group took a
    // new identity, forgetting it, before it asked -- or from inside this one, replacing a record
    // it lost track of.
    assert(!admitting || !ours || *ours == theirs);

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    // Joined at the user's choice, which is later than any dissolution of the group heard of
    // before.
    if (admitting) {
        _set_group_id(theirs);
        c.prepared_exec(
                "DELETE FROM device_dissolved_groups WHERE group_id = ?",
                std::span<const std::byte>{theirs.value});
    }

    // Merge incoming account keys.  New seeds are inserted and the rotation trigger applies
    // tie-breaking: latest created wins (smallest seed as tiebreaker), so concurrent rotations
    // from multiple devices converge deterministically.  For seeds we already have, we reconcile
    // the `rotated` column: if both sides have rotated at different times, take the minimum; if
    // only one side has rotated, adopt that rotation.
    //
    // Distributed, whoever minted it: the message it came in is in the swarm, carrying it to every
    // member, so it is owed by no push of ours -- not even one we minted ourselves, since a
    // message carrying it back means our push of it got there.
    std::vector<int64_t> carried_keys;
    for (const auto& k : payload.account_keys) {
        auto keys = keys_from_seed<AccountKeys>(k.seed);
        carried_keys.push_back(c.prepared_get<int64_t>(
                "INSERT INTO device_account_keys"
                " (created, rotated, seed, pubkey_mlkem768, pubkey_x25519, distributed)"
                " VALUES (?, ?, ?, ?, ?, 1)"
                " ON CONFLICT (seed) DO UPDATE SET"
                "   rotated = COALESCE(MIN(excluded.rotated, rotated), excluded.rotated, rotated),"
                "   distributed = 1"
                " RETURNING id",
                k.created,
                k.rotated,
                k.seed,
                keys.mlkem768_pub,
                keys.x25519_pub));
    }
    std::vector<device::Id> recipients;
    for (const auto& [id, info] : payload.devices)
        if (info.state == device::State::Registered)
            recipients.push_back(id);
    _record_key_delivery(carried_keys, recipients);

    bool removed = false;
    std::vector<device::Id> members;
    for (const auto& [id, info] : payload.devices) {
        if (tombstoned(info)) {
            // Whatever details we already hold are kept; only the state and the timestamp move.  A
            // device we have never heard of gets a bare tombstone -- see TOMBSTONE_SQL.
            assert(info.kicked);
            auto was =
                    c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", id)
                            .value_or(static_cast<int>(device::State::Unregistered));
            if (c.prepared_maybe_get<int64_t>(
                        TOMBSTONE_SQL,
                        info.kicked->time_since_epoch().count(),
                        id,
                        static_cast<int>(info.state))) {
                _devices_changed = true;
                // Gone from the group, rather than a tombstone for a device we never knew of.
                if (was == static_cast<int>(device::State::Registered) && id != self_id) {
                    members.push_back(id);
                    if (info.state == device::State::Kicked)
                        removed = true;
                }
            }
            continue;
        }

        // A removal is one-way: a device we hold a tombstone for cannot be returned to the group by
        // a record in a message, only by a fresh link request under a new device id.  Anything
        // claiming otherwise is either a device that was removed (or left) and is re-adding itself
        // -- it still holds the account seed, so it can sign and push whatever it likes -- or a
        // device relaying such a record.  Either way the answer is to restate the removal rather
        // than to adopt it.
        //
        // Asks the state, which now says only this: Left and Kicked are a device gone and nothing
        // else, where `Unregistered` covers a device that was never in the group -- our own row
        // before the group is established, and an ignored link request -- both of which must still
        // be able to register.
        auto gone = c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", id)
                            .value_or(-1) >= static_cast<int>(device::State::Left);
        if (gone) {
            log::warning(
                    cat,
                    "Device group message tried to restore removed device {}; restating removal",
                    oxenc::to_hex(id));
            c.prepared_exec(REASSERT_TOMBSTONE_SQL, epoch_seconds(clock_now_s()), id);
            _devices_changed = true;
            continue;
        }

        // Check state before upsert to detect a registration transition.
        bool was_registered =
                c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", id)
                        .value_or(-1) == static_cast<int>(device::State::Registered);

        auto dev_id = upsert_device_info(c, info);
        if (!dev_id)
            continue;
        _devices_changed = true;

        // Only on a state transition, not an update to a device already registered.
        if (!was_registered) {
            c.prepared_exec(ANSWER_REQUEST_SQL, *dev_id);
            if (id != self_id)
                members.push_back(id);
        } else {
            answer_replacements(c, *dev_id, id, info);
        }
    }

    // A removed device knows our device pubkeys, and could encrypt to them a group message of its
    // own making; rotating soon makes what it knows go stale.  The account key it may hold is
    // `next_account_rotation`'s to deal with.
    if (removed)
        _pull_in_device_rotation();

    _note_read(t);

    // Recorded whether or not the merge changed anything: a message that told us only what we
    // already knew is just as redundant as one that told us something new, and our next push
    // carries its contents either way.  A message we could not decrypt never reaches here.
    if (!hash.empty())
        c.prepared_exec(
                "INSERT INTO device_group_merged (hash) VALUES (?) ON CONFLICT DO NOTHING", hash);

    tx.commit();

    // Being admitted, every member is new to us, and none of them is news.  And joining is the
    // user's choice of this group over any other in view, as starting one would have been.
    if (admitting) {
        _forget_own_requests();
        core.globals.erase(dissolved_key);
        _dissolve_all_but(theirs);
    } else
        _member_changes.insert(_member_changes.end(), members.begin(), members.end());
}

void Devices::leave_group(result_function<bool> cb) {
    async([this] { return _leave_group(); }, std::move(cb));
}

bool Devices::leave_group(await_t) {
    return jq().call_get([this] { return _leave_group(); });
}

bool Devices::_leave_group() {
    assert(on_loop());
    if (!_group_id() && !core.globals.get_integer(dissolved_key))
        return false;

    // Outside the transaction, which it would otherwise nest inside; a crash after it leaves only a
    // spare device key.
    rotate_device_keys();

    // Only a member in good standing speaks for the group.  A removed device's departure could not
    // lower its removal, and a displaced one's would be taken as the departure of whichever device
    // now holds its id there.  A dropped one's would bring back a group gone from the swarm beside
    // another, or come from a device that may itself have been displaced.
    bool member = _member();
    auto devs = member ? devices(true, true, true) : device::map{};

    // The departure and the leaving commit together.  Queued alone, a crash before the leaving
    // would leave us sending a departure for a group we go on acting in, under an id the group
    // then holds as departed.
    device::Id id;
    {
        auto c = conn();
        SQLite::Transaction tx{c.sql};
        if (member)
            _queue_departure(devs);

        // Under a new id, as any device leaving its group: a record of ours in the group left can
        // then never meet one in the next, and asking to join the same group again is asking as a
        // new device.
        id = _forget_identity();
        tx.commit();
    }
    _adopt_identity(id);
    log::info(cat, "Left the device group");
    _send_pending_pushes();

    _devices_changed = true;
    _rebaseline_membership();
    _flush_events();
    return true;
}

void Devices::_queue_departure(device::map& devs) {
    bool others = std::ranges::any_of(devs, [this](const auto& d) {
        return d.first != self_id && d.second.state == device::State::Registered;
    });

    auto messages = _merged_hashes();

    // With nobody left the group is dissolved rather than departed: its messages deleted, and a
    // tombstone naming it.  Deleting alone would leave the devices of any other group on the
    // account, which cannot see a deletion, holding it as a fork in view until it lapsed -- and a
    // stale copy of it coming back is then dissolved again by whatever group we join next.
    if (!others) {
        auto ours = *_group_id();
        _queue_dissolution(std::span{&ours, 1}, std::move(messages));
        return;
    }

    // A departure for the members left, so they stop encrypting to us and rotate to a key we do
    // not hold, pushed as an ordinary group message: so it replaces the group's messages as any
    // push does.  Complete in itself, so nothing about sending it needs the group about to be
    // forgotten.
    auto& self = devs.at(self_id);
    self.state = device::State::Left;
    self.kicked = clock_now_s();
    _queue_push(encrypt_device_data(devs), std::move(messages));
}

std::vector<std::string> Devices::_merged_hashes() {
    std::vector<std::string> hashes;
    for (auto hash : conn().prepared_results<std::string>("SELECT hash FROM device_group_merged"))
        hashes.push_back(std::move(hash));
    return hashes;
}

bool Devices::_record_group(const SwarmMessage& msg) {
    oxenc::bt_dict_consumer in{msg.data};
    in.require<std::string_view>("");
    auto encrypted_id = in.require_span<std::byte, 8>("@");
    auto A = in.require_span<std::byte, 32>("A");
    auto X = in.require_span<std::byte, 32>("X");

    // Checked even though only a seed holder could have encrypted the identifier: without the
    // signature a storage server could still replay one group's identifier with a link key of its
    // own, and have requests to join that group encrypted to it.
    auto t = _signed_time(in, "device group message");

    device::GroupId group;
    {
        auto seed = core.globals.account_seed();
        group.value = crypt_group_id(encrypted_id, A, seed.seed());
    }

    // A dissolved group stays dissolved.  An older message of it is only a leftover the dissolving
    // device did not know to delete.  One written since is a device of it that never heard, back
    // after the tombstone expired, and never a group the user has chosen since: beside the kept
    // group that device would have been dropped, so it can only have pushed into a swarm the kept
    // group had lapsed from.  A device in a group tells it again, forked or dropped as it may be,
    // since that decides nothing.  A device outside one takes it as it would any other group.
    if (auto dissolved = _dissolved_at(group)) {
        bool back = t > *dissolved;
        if (_registered()) {
            std::vector<std::string> hashes;
            if (!msg.hash.empty())
                hashes.push_back(msg.hash);
            if (back) {
                log::warning(
                        cat, "A dissolved device group is in the swarm again; dissolving it again");
                _dissolve(std::span{&group, 1}, std::move(hashes));
            } else
                _delete_from_swarm(std::move(hashes), "a dissolved device group's message");
            return false;
        }
        if (!back)
            return false;
    }

    auto c = conn();
    c.prepared_exec(
            "INSERT INTO device_groups (group_id, link_x25519, seen_at, expires_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(group_id) DO UPDATE SET"
            "   link_x25519 = CASE WHEN excluded.seen_at >= seen_at"
            "       THEN excluded.link_x25519 ELSE link_x25519 END,"
            "   seen_at = MAX(seen_at, excluded.seen_at),"
            "   expires_at = MAX(expires_at, excluded.expires_at)",
            std::span<const std::byte>{group.value},
            X,
            epoch_seconds(std::chrono::floor<std::chrono::seconds>(t)),
            epoch_seconds(std::chrono::floor<std::chrono::seconds>(msg.expiry)));

    c.prepared_exec(
            "DELETE FROM device_group_messages WHERE expires_at <= ?",
            epoch_seconds(clock_now_s()));
    if (!msg.hash.empty())
        c.prepared_exec(
                "INSERT INTO device_group_messages (hash, group_id, expires_at) VALUES (?, ?, ?)"
                " ON CONFLICT DO NOTHING",
                msg.hash,
                std::span<const std::byte>{group.value},
                epoch_seconds(std::chrono::floor<std::chrono::seconds>(msg.expiry)));
    return true;
}

void Devices::_mark_dissolved(const device::GroupId& group, sys_ms t) {
    auto c = conn();
    auto id = std::span<const std::byte>{group.value};
    c.prepared_exec(
            "INSERT INTO device_dissolved_groups (group_id, dissolved_at) VALUES (?, ?)"
            " ON CONFLICT(group_id) DO UPDATE SET"
            "   dissolved_at = MAX(dissolved_at, excluded.dissolved_at)",
            id,
            epoch_ms(t));
    c.prepared_exec("DELETE FROM device_groups WHERE group_id = ?", id);
    c.prepared_exec("DELETE FROM device_group_messages WHERE group_id = ?", id);
}

std::vector<std::byte> Devices::_build_dissolution(
        std::span<const device::GroupId> groups, sys_ms t) {
    std::vector<std::byte> ids;
    for (const auto& g : groups)
        ids.insert(ids.end(), g.value.begin(), g.value.end());

    // Nothing is encrypted to anyone, so A is only what makes the encrypted ids differ from one
    // tombstone to the next.
    auto A = x25519::keypair().first;
    std::vector<std::byte> encrypted(ids.size());
    {
        auto seed = core.globals.account_seed();
        crypt_group_ids(encrypted, ids, A, seed.seed());
    }

    oxenc::bt_dict_producer o;
    o.append("", "T");
    o.append("@", std::span<const std::byte>{encrypted});
    o.append("A", A);
    o.append("t", epoch_ms(t));
    o.append_signature("~", [seed = core.globals.account_seed()](std::span<const std::byte> body) {
        return ed25519::sign(seed.ed25519_secret(), body);
    });
    return to_vector<std::byte>(std::move(o).str());
}

void Devices::_dissolve(
        std::span<const device::GroupId> groups, std::vector<std::string> obsolete) {
    assert(on_loop());
    {
        auto c = conn();
        SQLite::Transaction tx{c.sql};
        _queue_dissolution(groups, std::move(obsolete));
        tx.commit();
    }
    log::info(cat, "Dissolved {} other device group(s)", groups.size());
    _send_pending_pushes();
}

void Devices::_queue_dissolution(
        std::span<const device::GroupId> groups, std::vector<std::string> obsolete) {
    auto t = clock_now_ms();
    auto c = conn();
    for (const auto& group : groups) {
        for (auto hash : c.prepared_results<std::string>(
                     "SELECT hash FROM device_group_messages WHERE group_id = ?",
                     std::span<const std::byte>{group.value}))
            obsolete.push_back(std::move(hash));
        _mark_dissolved(group, t);
    }
    // A hash can be both one the caller had and one of the group's we saw.
    std::ranges::sort(obsolete);
    auto [dup, end] = std::ranges::unique(obsolete);
    obsolete.erase(dup, end);

    // Never renewed, and never among what a group push deletes: it is there to tell the dissolved
    // group's devices that are online now, and lapses with the messages it replaced.
    _queue_push(_build_dissolution(groups, t), std::move(obsolete));
}

void Devices::_dissolve_all_but(const device::GroupId& kept) {
    std::vector<device::GroupId> others;
    for (auto group : conn().prepared_results<sqlite::blob_guts<std::array<std::byte, 8>>>(
                 "SELECT group_id FROM device_groups WHERE group_id != ? AND expires_at > ?",
                 std::span<const std::byte>{kept.value},
                 epoch_seconds(clock_now_s())))
        others.push_back(device::GroupId{group});
    if (!others.empty())
        _dissolve(others);
}

void Devices::_record_key_delivery(
        std::span<const int64_t> keys, std::span<const device::Id> devices) {
    auto c = conn();
    for (auto key : keys)
        for (const auto& device : devices)
            c.prepared_exec(
                    "INSERT INTO device_account_key_recipients (key, device)"
                    " SELECT id, ? FROM device_account_keys WHERE id = ?"
                    " ON CONFLICT DO NOTHING",
                    device,
                    key);
}

std::vector<device::Id> Devices::_key_recipients(int64_t key) {
    std::vector<device::Id> out;
    for (auto id : conn().prepared_results<sqlite::blob_guts<device::Id>>(
                 "SELECT device FROM device_account_key_recipients WHERE key = ?", key))
        out.push_back(id);
    return out;
}

bool Devices::_key_held_outside(int64_t key, bool ours) {
    return conn()
            .prepared_maybe_get<int>(
                    "SELECT 1 FROM device_account_key_recipients r"
                    " JOIN devices d ON d.unique_id = r.device"
                    " WHERE r.key = ? AND d.state IN (?, ?) AND (? = 0 OR d.removed_by_us)",
                    key,
                    static_cast<int>(device::State::Kicked),
                    static_cast<int>(device::State::Left),
                    ours ? 1 : 0)
            .has_value();
}

void Devices::_queue_push(
        std::optional<std::vector<std::byte>> message, std::vector<std::string> obsolete) {
    if (!message && obsolete.empty())
        return;
    oxenc::bt_list_producer hashes;
    for (const auto& h : obsolete)
        hashes.append(h);
    auto encoded = std::move(hashes).str();
    conn().prepared_exec(
            "INSERT INTO device_pending_pushes (message, obsolete, created_at) VALUES (?, ?, ?)",
            message ? std::optional{std::span<const std::byte>{*message}} : std::nullopt,
            to_span<std::byte>(encoded),
            epoch_seconds(clock_now_s()));
}

void Devices::_send_pending_pushes() {
    assert(on_loop());
    auto c = conn();
    c.prepared_exec(
            "DELETE FROM device_pending_pushes WHERE created_at <= ?",
            epoch_seconds(clock_now_s() - DEVICE_GROUP_TTL));
    if (!core.network())
        return;

    struct Pending {
        int64_t row;
        std::optional<std::vector<std::byte>> message;
        std::vector<std::string> obsolete;
    };
    // Read out before any is sent: an answer can come back within the send, and delete its row.
    std::vector<Pending> pending;
    for (auto [row, has_message, message, obsolete] :
         c.prepared_results<int64_t, int, sqlite::blob, sqlite::blob>(
                 "SELECT id, message IS NOT NULL, IFNULL(message, X''), obsolete"
                 " FROM device_pending_pushes ORDER BY id")) {
        if (_pending_in_flight.contains(row))
            continue;
        auto& p = pending.emplace_back();
        p.row = row;
        if (has_message)
            p.message.emplace(message.begin(), message.end());
        oxenc::bt_list_consumer hashes{std::span<const std::byte>{obsolete}};
        while (!hashes.is_finished())
            p.obsolete.push_back(hashes.consume_string());
    }

    for (auto& p : pending) {
        _pending_in_flight.insert(p.row);
        bool storing = p.message.has_value();
        std::vector<SwarmStore> stores;
        if (storing)
            stores.push_back(
                    {.ns = config::Namespace::Devices,
                     .data = std::move(*p.message),
                     .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(
                             DEVICE_GROUP_TTL)});
        core._swarm_push(
                std::move(stores),
                std::move(p.obsolete),
                [this, alive = std::weak_ptr<int>{_alive}, row = p.row, storing](
                        std::optional<std::vector<SwarmStoreResult>> results) {
                    if (alive.expired())
                        return;
                    _pending_in_flight.erase(row);
                    if (!results || (storing && (results->empty() || !results->front().stored))) {
                        log::warning(cat, "A pending device group push was not stored; will retry");
                        _push_failed();
                        return;
                    }
                    _push_stored();
                    conn().prepared_exec("DELETE FROM device_pending_pushes WHERE id = ?", row);
                });
    }
}

void Devices::_delete_from_swarm(std::vector<std::string> hashes, std::string_view what) {
    if (hashes.empty())
        return;
    if (core.network())
        core._swarm_push({}, std::move(hashes), [what = std::string{what}](auto results) {
            if (!results)
                log::warning(cat, "Could not delete {} from the swarm", what);
        });
    else
        log::warning(cat, "Not deleting {} from the swarm: no network", what);
}

void Devices::receive_dissolution(std::span<const std::byte> data) {
    oxenc::bt_dict_consumer in{data};
    in.require<std::string_view>("");
    auto encrypted = in.require_span<std::byte>("@");
    if (encrypted.empty() || encrypted.size() % sizeof(device::GroupId::value) != 0)
        throw std::runtime_error{
                "Invalid dissolution: {}-byte group list"_format(encrypted.size())};
    auto A = in.require_span<std::byte, 32>("A");
    auto t = _signed_time(in, "dissolution");

    std::vector<std::byte> ids(encrypted.size());
    {
        auto seed = core.globals.account_seed();
        crypt_group_ids(ids, encrypted, A, seed.seed());
    }

    std::vector<device::GroupId> named(ids.size() / sizeof(device::GroupId::value));
    for (size_t i = 0; i < named.size(); i++) {
        auto& id = named[i].value;
        std::memcpy(id.data(), ids.data() + i * id.size(), id.size());
    }

    // The user of another device kept another group over this one.  Nothing of this group is any
    // use now, our id included: the way back is to ask to join the group that was kept, as a new
    // device.
    //
    // All of it in one commit with the groups it marks dissolved, so that no crash leaves this
    // device holding a group the tombstone named, or forgotten from it but not told it is
    // Dissolved.
    auto ours = _group_id();
    bool dissolved = ours && std::ranges::find(named, *ours) != named.end();
    if (dissolved) {
        log::warning(cat, "This device's group was dissolved by another of the account's devices");
        // Before the transaction, which it would otherwise nest inside.
        rotate_device_keys();
    }

    std::optional<device::Id> id;
    {
        auto c = conn();
        SQLite::Transaction tx{c.sql};
        if (dissolved) {
            id = _forget_identity();
            core.globals.set(dissolved_key, int64_t{1});
        }
        for (const auto& group : named)
            _mark_dissolved(group, t);
        tx.commit();
    }
    if (id) {
        _adopt_identity(*id);
        _devices_changed = true;
    }
}

device::Membership Devices::_unreadable_verdict(std::span<const std::byte> data) {
    oxenc::bt_dict_consumer in{data};
    in.require<std::string_view>("");
    auto A = in.require_span<std::byte, 32>("A");
    std::span<const std::byte> kicked;
    if (in.skip_until("k"))
        kicked = in.consume_span<std::byte>();
    auto t = from_epoch_ms(in.require<int64_t>("t"));

    // No removal carried at all: had ours happened since we last read the group, it would be, being
    // the only one and recent enough not to have been pruned.
    if (kicked.empty()) {
        auto read_at = core.globals.get_integer(read_at_key);
        return read_at && from_epoch_ms(*read_at) > t - REMOVAL_MARKER_MAX_AGE
                     ? device::Membership::Displaced
                     : device::Membership::Dropped;
    }
    if (kicked.size() % 16 != 0)
        return device::Membership::Dropped;

    auto seed = core.globals.account_seed();
    auto names = [&](std::span<const std::byte, device::ID_SIZE> id) {
        auto entry = kicked_entry(A, seed.seed(), id);
        for (size_t i = 0; i < kicked.size(); i += 16)
            if (std::ranges::equal(kicked.subspan(i, 16), entry))
                return true;
        return false;
    };
    if (names(self_id))
        return device::Membership::Removed;

    // A message carries its group's most recent removals, so one carrying a removal we already knew
    // of, from before we lost the group, carries every removal since -- ours, had it happened.
    for (auto id : conn().prepared_results<sqlite::blob_guts<device::Id>>(
                 "SELECT unique_id FROM devices WHERE state = ?",
                 static_cast<int>(device::State::Kicked)))
        if (names(id))
            return device::Membership::Displaced;
    return device::Membership::Dropped;
}

// Runs `f`, reporting to `cb` whatever it throws.  Once `f` hands `cb` on, moving from it, nothing
// it does may throw, so that `cb` hears at most once either way.
template <typename T, typename F>
static void reporting_failure(result_function<T>& cb, F&& f) {
    try {
        f();
    } catch (const std::exception& e) {
        detail::log_component_failure(e);
        if (cb)
            cb(unexpected{error_from(e)});
    }
}

void Devices::request_link(device::GroupId group, result_function<OutgoingLinkRequest> cb) {
    enqueue([this, group, cb = std::move(cb)]() mutable {
        reporting_failure(cb, [&] { _request_link(group, cb); });
    });
}

void Devices::_request_link(
        const device::GroupId& group, result_function<OutgoingLinkRequest>& cb) {
    assert(on_loop());

    // Also what stops a device with no account getting as far as building a request, since a
    // network cannot be attached without one.
    if (!core.network())
        throw session::error{err::network_unavailable, "Cannot request a link: no network"};
    _cast_out_asking();

    // Encrypted to the link key the group publishes now, rather than as of whenever we last
    // fetched: one that has since reached a removed device is a key the group refuses requests
    // under.  The fetch also shows whether the group is still there at all, and brings in an
    // admission on a request already out.
    core._fetch(
            {config::Namespace::Devices},
            [this, alive = std::weak_ptr<int>{_alive}, group, cb = std::move(cb)](
                    bool fetched) mutable {
                if (alive.expired())
                    return;
                reporting_failure(cb, [&] {
                    if (!fetched)
                        throw session::error{
                                err::network_unavailable,
                                "Cannot request a link: could not fetch the device group"};
                    _send_link_request(group, cb);
                });
            });
}

bool Devices::_cast_out_asking() {
    bool cast_out = _cast_out();
    if (!cast_out && _device_info().second)
        throw session::error{
                err::already_registered,
                "This device is in a group; it must leave it before asking to join another"};
    return cast_out;
}

void Devices::_send_link_request(
        const device::GroupId& group, result_function<OutgoingLinkRequest>& cb) {
    assert(on_loop());
    // Again, since the fetch may have changed it.
    bool cast_out = _cast_out_asking();

    // Asking again while a request for the group is out is reopening it: a new one would show the
    // user new emoji, and take the place of the one another device may be approving now.
    if (auto newest = _newest_request(); newest && newest->group == group)
        if (auto live = _outgoing_link_request()) {
            if (cb)
                cb(*live);
            return;
        }

    auto link_x25519 = conn().prepared_maybe_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
            "SELECT link_x25519 FROM device_groups WHERE group_id = ? AND expires_at > ?",
            std::span<const std::byte>{group.value},
            epoch_seconds(clock_now_s()));
    if (!link_x25519)
        throw session::error{
                err::unknown_group, "Cannot request a link: no such group is in the swarm"};

    // Its id is spent in the group that removed it, and another device's in the one it was
    // displaced from: it can only ask as a new device, whichever group it asks.
    if (cast_out)
        _new_identity();

    auto req = _build_link_request(group, *link_x25519);
    OutgoingLinkRequest sent{.sas = req.sas, .expires = clock_now_s() + LINK_REQUEST_TTL};

    std::vector<SwarmStore> stores;
    stores.push_back(
            {.ns = config::Namespace::Devices,
             .data = std::move(req.message),
             .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(LINK_REQUEST_TTL)});

    core._swarm_push(
            std::move(stores),
            {},
            [this, alive = std::weak_ptr<int>{_alive}, row = req.row, sent, cb = std::move(cb)](
                    std::optional<std::vector<SwarmStoreResult>> results) {
                if (alive.expired())
                    return;

                // Whether a later request has replaced this one, so that the user is now looking at
                // that one instead.
                auto newest = _newest_request();
                bool current = newest && newest->row == row;

                if (results && !results->empty() && results->front().stored) {
                    conn().prepared_exec(
                            "UPDATE device_own_requests SET expires_at = ? WHERE id = ?",
                            epoch_seconds(sent.expires),
                            row);
                    if (current)
                        _flush_events();
                    if (cb)
                        cb(sent);
                    return;
                }

                // Nothing was sent that another device could accept, so nothing is outstanding --
                // unless a later request has replaced this one, which is still in flight.  The
                // caller hears it failed, so hearing that we stopped waiting as well would be news
                // twice.
                conn().prepared_exec("DELETE FROM device_own_requests WHERE id = ?", row);
                if (current && _withdraw_own_request())
                    _rebaseline_membership();
                if (cb)
                    cb(unexpected{Error{err::store_failed, "The swarm did not store the request"}});
            });

    _flush_events();
}

void Devices::outgoing_link_request(result_function<std::optional<OutgoingLinkRequest>> cb) {
    async([this] { return _outgoing_link_request(); }, std::move(cb));
}

std::optional<Devices::OutgoingLinkRequest> Devices::outgoing_link_request(await_t) {
    return jq().call_get([this] { return _outgoing_link_request(); });
}

template <typename... T>
std::optional<Devices::OwnRequest> Devices::_select_own_request(
        std::string_view where, const T&... bind) {
    assert(on_loop());
    auto found = conn().prepared_maybe_get<
            int64_t,
            sqlite::blob_guts<std::array<std::byte, 8>>,
            sqlite::blob_guts<std::array<std::byte, 16>>,
            int64_t,
            std::optional<int64_t>,
            int>(
            "SELECT id, group_id, sas_seed, timestamp, expires_at, admission IS NOT NULL"
            "  FROM device_own_requests {} ORDER BY id DESC LIMIT 1"_format(where),
            bind...);
    if (!found)
        return std::nullopt;
    auto& [row, group, seed, asked, expires, held] = *found;
    return OwnRequest{
            .row = row,
            .group = device::GroupId{group},
            .sas_seed = seed,
            .asked = from_epoch_s(asked),
            .expires = expires ? std::optional{from_epoch_s(*expires)} : std::nullopt,
            .held = held != 0};
}

std::optional<Devices::OwnRequest> Devices::_newest_request() {
    return _select_own_request("");
}

std::optional<Devices::OwnRequest> Devices::_own_request_admitted(
        const device::GroupId& group, const device::Info& record) {
    return _select_own_request(
            "WHERE group_id = ? AND timestamp = ? AND pubkey_x25519 = ?",
            std::span<const std::byte>{group.value},
            record.timestamp.time_since_epoch().count(),
            record.pk_x25519);
}

std::optional<std::chrono::sys_seconds> Devices::_own_deadline() {
    auto newest = _newest_request();
    if (!newest || newest->held || !newest->expires)
        return std::nullopt;
    // Past it only until the withdrawal it calls for, after which nothing waits on it.
    if (*newest->expires > clock_now() || conn().prepared_maybe_get<int>(
                                                  "SELECT 1 FROM devices"
                                                  " WHERE unique_id = ? AND state = ?",
                                                  self_id,
                                                  static_cast<int>(device::State::Pending)))
        return newest->expires;
    return std::nullopt;
}

std::optional<Devices::OutgoingLinkRequest> Devices::_outgoing_link_request() {
    assert(on_loop());
    auto newest = _newest_request();
    // Nothing until the swarm has stored it, which is when another device can see it -- unless an
    // admission on it is waiting, which shows that one did.
    if (!newest || !(newest->held || (newest->expires && *newest->expires > clock_now())))
        return std::nullopt;

    return OutgoingLinkRequest{
            .sas = sas_from_seed(newest->sas_seed),
            .expires = newest->expires.value_or(newest->asked + LINK_REQUEST_TTL)};
}

void Devices::confirm_link(result_function<bool> cb) {
    async([this] { return _confirm_link(); }, std::move(cb));
}

bool Devices::confirm_link(await_t) {
    return jq().call_get([this] { return _confirm_link(); });
}

bool Devices::_confirm_link() {
    assert(on_loop());
    auto newest = _newest_request();
    if (!newest || !newest->held)
        return false;

    std::vector<std::byte> admission;
    std::string hash;
    for (auto [data, h] : conn().prepared_results<sqlite::blob, std::string>(
                 "SELECT admission, admission_hash FROM device_own_requests WHERE id = ?",
                 newest->row)) {
        admission.assign(data.begin(), data.end());
        hash = std::move(h);
    }
    receive_device_group_message(admission, hash, true);
    if (_member())
        _reread_account_pubkeys();
    _flush_events();
    return true;
}

void Devices::_forget_own_requests() {
    conn().prepared_exec("DELETE FROM device_own_requests");
}

bool Devices::_withdraw_own_request() {
    assert(on_loop());
    return conn()
            .prepared_maybe_get<int64_t>(
                    "UPDATE devices SET state = ? WHERE unique_id = ? AND state = ? RETURNING id",
                    static_cast<int>(device::State::Unregistered),
                    self_id,
                    static_cast<int>(device::State::Pending))
            .has_value();
}

Devices::LinkRequestResult Devices::_build_link_request(
        const device::GroupId& group, std::span<const std::byte, 32> link_x25519) {
    assert(on_loop());
    auto [info, is_registered] = _device_info();
    auto c = conn();

    // A new record even if nothing it says has changed, since it is stamped anew: after every
    // request before it, even within the same second, because the timestamp is what tells an
    // admission which of our requests it accepted.
    auto held = _held_record();
    info.seqno = (held ? held->seqno : 0) + 1;
    info.timestamp = std::max(
            clock_now_s(),
            from_epoch_s(c.prepared_get<int64_t>(
                    "SELECT IFNULL(MAX(timestamp) + 1, 0) FROM device_own_requests")));

    // Our own row moves to Pending with the updated seqno, timestamp, and pubkeys: Pending is what
    // says we are waiting.
    assert(!is_registered);
    auto ver = info.version[0] * 1000000 + info.version[1] * 1000 + info.version[2];
    c.prepared_exec(
            R"(INSERT INTO devices
                (unique_id, state, seqno, timestamp, device_type, description, version,
                 pubkey_mlkem768, pubkey_x25519)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(unique_id) DO UPDATE SET
                   state = excluded.state,
                   seqno = excluded.seqno,
                   timestamp = excluded.timestamp,
                   device_type = excluded.device_type,
                   description = excluded.description,
                   version = excluded.version,
                   pubkey_mlkem768 = excluded.pubkey_mlkem768,
                   pubkey_x25519 = excluded.pubkey_x25519)",
            self_id,
            static_cast<int>(device::State::Pending),
            info.seqno,
            info.timestamp.time_since_epoch().count(),
            info.encoded_type(),
            info.description,
            ver,
            info.pk_mlkem768,
            info.pk_x25519);

    auto seed = core.globals.account_seed();
    auto plaintext = encode_link_request_plaintext(self_id, info, seed.ed25519_secret());
    auto sas_seed = derive_sas_seed(to_span<std::byte>(plaintext));
    auto out = _encrypt_link_request(to_span(plaintext), link_x25519);

    // An admission held for an earlier request is let go: the user has moved on to this one, whose
    // emoji are what they will now confirm.  Requests too old for any admission to still be in the
    // swarm go too.
    c.prepared_exec(
            "UPDATE device_own_requests"
            " SET admission = NULL, admission_hash = NULL");
    c.prepared_exec(
            "DELETE FROM device_own_requests WHERE timestamp < ?",
            epoch_seconds(clock_now_s() - LINK_REQUEST_TTL - DEVICE_GROUP_TTL));
    auto row = c.prepared_get<int64_t>(
            "INSERT INTO device_own_requests (group_id, timestamp, pubkey_x25519, sas_seed)"
            " VALUES (?, ?, ?, ?) RETURNING id",
            std::span<const std::byte>{group.value},
            info.timestamp.time_since_epoch().count(),
            info.pk_x25519,
            sas_seed);

    // Now waiting on our own request, which the caller knows: it is the one asking.
    _rebaseline_membership();

    return {std::move(out), sas_from_seed(sas_seed), row};
}

std::vector<std::byte> Devices::_encrypt_link_request(
        std::span<const std::byte> plaintext, std::span<const std::byte, 32> link_x25519) {
    // Encrypted to the group being asked, so that only its members can read it -- not every holder
    // of the seed, which includes any device ever removed.  See "Initiating a device link".
    auto [E, e] = x25519::keypair();
    cleared_b32 shared_x, shared_s;
    const auto& S = core.globals.pubkey_x25519();
    if (!x25519::scalarmult(shared_x, e, link_x25519) || !x25519::scalarmult(shared_s, e, S))
        throw std::runtime_error{"Cannot encrypt a link request: degenerate X25519 key"};
    auto kiss = link_request_kiss(shared_s, E, S);
    std::array<std::byte, 2> indicator{link_x25519[0] ^ kiss[0], link_x25519[1] ^ kiss[1]};

    auto [key, nonce] = link_request_key(shared_x, E, link_x25519);
    std::vector<std::byte> encrypted(plaintext.size() + encryption::XCHACHA20_ABYTES);
    encryption::xchacha20poly1305_encrypt(encrypted, plaintext, nonce, key);

    std::vector<std::byte> out(
            2                                         // Outer "d" ... "e" delimiters
            + 5                                       // "0:" + "1:L" (message type indicator)
            + 3 + bt_bytes_encoded(E.size())          // "1:E" + "32:...(ephemeral pubkey)..."
            + 3 + bt_bytes_encoded(encrypted.size())  // "1:L" + "NNN:...(encrypted request)..."
            + 3 + bt_bytes_encoded(indicator.size())  // "1:i" + "2:...(key indicator)..."
    );
    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};
    o.append("", "L");
    o.append("E", E);
    o.append("L", std::span<const std::byte>{encrypted});
    o.append("i", indicator);
    assert(o.view().size() == out.size());
    return out;
}

std::vector<std::byte> Devices::decrypt_device_data(std::span<const std::byte> enc_data) {

    oxenc::bt_dict_consumer in{enc_data};
    in.require<std::string_view>("");  // skip the "" type key added by the outer wrapper
    auto A = in.require_span<std::byte, 32>("A");
    auto ciphertext_raw = in.require_span<std::byte>("C");
    auto enc_key_raw = in.require_span<std::byte>("K");
    auto enc_devices = in.require_span<std::byte>("d");

    _verify_account_signature(in, "encrypted device message");

    in.finish();

    if (ciphertext_raw.size() % mlkem768::CIPHERTEXTBYTES != 0)
        throw std::runtime_error{
                "Invalid encrypted device group data: invalid ciphertext size ({} is not N*{})"_format(
                        ciphertext_raw.size(), mlkem768::CIPHERTEXTBYTES)};
    const int count = ciphertext_raw.size() / mlkem768::CIPHERTEXTBYTES;
    if (enc_key_raw.size() % (32 + 2) != 0)
        throw std::runtime_error{
                "Invalid encrypted device group data: invalid encrypted keys size ({} is not N*34)"_format(
                        enc_key_raw.size())};
    if (const int k_count = enc_key_raw.size() / (32 + 2); count != k_count)
        throw std::runtime_error{
                "Invalid encrypted device data: ciphertext ({}) vs enc key ({}) size mismatch"_format(
                        count, k_count)};
    if (enc_devices.size() <= encryption::XCHACHA20_ABYTES)
        throw std::runtime_error{
                "Invalid encrypted device data: encrypted data is too short ({}B)"_format(
                        enc_devices.size())};

    auto indices = std::views::iota(0, count);

    // Accessors for chunk-by-chunk access to the ciphertext_raw/enc_key_raw spans:
    auto ciphertext = indices | std::views::transform([&](int i) {
                          return std::span<const std::byte, mlkem768::CIPHERTEXTBYTES>{
                                  ciphertext_raw.data() + i * mlkem768::CIPHERTEXTBYTES,
                                  mlkem768::CIPHERTEXTBYTES};
                      });
    auto enc_indicator =
            indices | std::views::transform([&](int i) {
                return std::span<const std::byte, 2>{enc_key_raw.data() + i * (2 + 32), 2};
            });
    auto enc_key =
            indices | std::views::transform([&](int i) {
                return std::span<const std::byte, 32>{enc_key_raw.data() + i * (2 + 32) + 2, 32};
            });

    auto active_keys = active_device_keys();

    auto devices_nonce = hash::blake2b_key_pers<24>(A, PERS_DEV_NONCE, ciphertext_raw);

    cleared_b32 ml_ss, aB, ki, key_base;

    std::vector<std::byte> plaintext_devices;
    plaintext_devices.resize(enc_devices.size() - encryption::XCHACHA20_ABYTES);

    // Trial decrypt until we find one that works, except that we can skip most of the heavy
    // operations for most keys not intended for us.  Note that we have to attempt each received key
    // by all of our recent device keys because it might be a pre-rotation message encrypted using
    // an older key, so even if we have only 4 incoming values, we might have 20 recent device keys
    // meaning 80 potential decryptions.
    bool found = false;
    for (int i = 0; !found && i < count; i++) {
        auto ct = ciphertext[i];
        auto ekey = enc_key[i];
        auto eind = enc_indicator[i];

        auto knonce = hash::blake2b_key_pers<24>(A, PERS_KEY_NONCE, ct, enc_devices);

        for (int active_i = 0; active_i < active_keys.size(); active_i++) {
            const auto& k = active_keys[active_i];
            const auto& b = k.x25519_sec;
            const auto& B = k.x25519_pub;
            const auto& M = k.mlkem768_pub;

            // First work out the checksum hash; the vast majority of the time this won't match for
            // a key other than our own (only 1/65535 chance of collision), and so we can short
            // circuit and save a bunch of calculations.
            if (!std::ranges::equal(
                        hash::blake2b_pers<2>(PERS_KEY_KEY_IDX, A, B, M, ct, ekey), eind))
                continue;

            if (!x25519::scalarmult(aB, b, A)) {
                log::warning(cat, "X25519 multiplication failed; ignoring encrypted entry");
                continue;
            }

            if (!mlkem768::decapsulate(ml_ss, ct, k.mlkem768_sec)) {
                log::warning(cat, "MLKEM768 decapsulation failed; skipping device entry");
                continue;
            }

            // Now we have various shared secret data: hash it into the k[i] value that should have
            // been used to encrypt the key_base value for us:
            hash::blake2b_pers(ki, PERS_KEY_KEY, aB, A, B, ml_ss, M);

            // and then use it to recover the key_base:
            static_assert(decltype(ekey)::extent == key_base.size());
            encryption::xchacha20_xor(key_base, ekey, knonce, ki);

            // Now we can decrypt the encrypted payload:
            if (encryption::xchacha20poly1305_decrypt(
                        plaintext_devices, enc_devices, devices_nonce, key_base)) {
                found = true;
                break;
            }

            log::debug(
                    cat,
                    "Decryption of record {} against recent key {} failed; probably a checksum "
                    "false positive",
                    i,
                    active_i);
        }
    }

    if (!found) {
        // There are a bunch of reasons for this: maybe we aren't in the device group, maybe it was
        // corrupted, or many it is an old message and we don't have the keys for it anymore.
        log::warning(cat, "Failed to decrypt incoming device data");
        throw device::decryption_failed{"Failed to decrypt incoming device data"};
    }

    // Strip the padding appended before encryption.  The payload is a bt-encoded dict, which always
    // ends in 'e', so trailing null bytes are unambiguously padding rather than content.
    trim_trailing(plaintext_devices);

    return plaintext_devices;
}

std::optional<std::vector<std::byte>> Devices::_decrypt_link_request(
        std::span<const std::byte, 32> E,
        std::span<const std::byte> encrypted,
        std::span<const std::byte, 2> indicator) {
    if (encrypted.size() < encryption::XCHACHA20_ABYTES)
        return std::nullopt;

    auto seed = core.globals.account_seed();
    cleared_b32 shared_s;
    if (!x25519::scalarmult(shared_s, seed.x25519_key(), E))
        return std::nullopt;
    auto kiss = link_request_kiss(shared_s, E, core.globals.pubkey_x25519());
    std::array<std::byte, 2> prefix{indicator[0] ^ kiss[0], indicator[1] ^ kiss[1]};

    // Any key we still hold, not only the current one: the group may have rotated since the
    // request's sender read its link key.
    for (auto [id, account_seed] : conn().prepared_results<int64_t, sqlite::blobn<32>>(
                 "SELECT id, seed FROM device_account_keys WHERE substr(pubkey_x25519, 1, 2) = ?",
                 std::span<const std::byte>{prefix})) {
        auto keys = keys_from_seed<AccountKeys>(account_seed);
        cleared_b32 shared_x;
        if (!x25519::scalarmult(shared_x, keys.x25519_sec, E))
            continue;
        auto [key, nonce] = link_request_key(shared_x, E, keys.x25519_pub);
        std::vector<std::byte> plaintext(encrypted.size() - encryption::XCHACHA20_ABYTES);
        if (!encryption::xchacha20poly1305_decrypt(plaintext, encrypted, nonce, key))
            continue;

        // Except one a device no longer in the group also holds.  Such a device can publish that
        // key as the group's link key, read the request encrypted to it, and admit the device
        // asking into a group of its own.  Prompting here would show the user matching emoji on a
        // real device, which is all the asking device's confirmation checks.
        if (_key_held_outside(id)) {
            log::info(cat, "Ignoring a link request under a key a removed device holds");
            return std::nullopt;
        }
        return plaintext;
    }
    return std::nullopt;
}

void Devices::receive_link_request(
        std::span<const std::byte> data, const std::string& hash, sys_ms expiry) {
    oxenc::bt_dict_consumer outer{data};
    outer.require<std::string_view>("");
    auto E = outer.require_span<std::byte, 32>("E");
    auto encrypted = outer.require_span<std::byte>("L");
    auto indicator = outer.require_span<std::byte, 2>("i");

    // Encrypted to one group's link key, so failing here is the ordinary case for a request asking
    // to join a different group.
    auto plaintext = _decrypt_link_request(E, encrypted, indicator);
    if (!plaintext) {
        log::debug(cat, "Ignoring a link request for a group this device is not in");
        return;
    }

    // {"I": device id, "i": device info dict, "~": signature by the account key}
    device::Info info;
    std::string_view raw;
    try {
        oxenc::bt_dict_consumer pt{std::span<const std::byte>{*plaintext}};
        auto in_id = pt.require_span<unsigned char, device::ID_SIZE>("I");
        std::memcpy(info.id.data(), in_id.data(), info.id.size());

        // Skip any unknown keys between "I" and "i"
        oxenc::bt_dict extra_outer;
        while (!pt.is_finished() && pt.key() < "i")
            consume_extra(pt, extra_outer);
        if (pt.is_finished() || pt.key() != "i")
            throw std::runtime_error{"missing 'i' device info dict"};
        raw = pt.consume_dict_data();
        decode_one(info, oxenc::bt_dict_consumer{raw}, device::State::Pending);
        info.digest = hash::blake2b<8>(raw);

        // The group's link key is published, so anything could have encrypted to it; only a seed
        // holder could have signed.
        _verify_account_signature(pt, "link request");
    } catch (const std::exception& e) {
        log::warning(cat, "Ignoring incoming link request: failed to parse: {}", e.what());
        return;
    }

    // Our own request, fetched back from the swarm we sent it to.  The merge guard below would also
    // turn it away, but only because our own row happens to carry no digest.
    if (info.id == self_id)
        return;

    auto c = conn();

    // A device already in the group is asking to replace its record: it lost track of having joined
    // -- restored from a backup, say -- and no longer holds the keys the group encrypts to.  Its
    // row keeps the record in use until the request is accepted.  A device that was removed, or
    // left, cannot ask at all: its id is spent.
    auto existing = c.prepared_maybe_get<int64_t, int, int64_t>(
            "SELECT id, state, timestamp FROM devices WHERE unique_id = ?", info.id);
    auto existing_state =
            existing ? static_cast<device::State>(std::get<1>(*existing)) : device::State::Pending;
    bool replaces = existing_state == device::State::Registered;

    // Only a request made after the record it would replace: an older one is the request that
    // admitted the device in the first place, or one it has since moved past, still in the swarm
    // and fetched late.
    if (replaces && info.timestamp.time_since_epoch().count() <= std::get<2>(*existing)) {
        log::debug(
                cat,
                "Ignoring link request from {}: older than its record in the group",
                oxenc::to_hex(info.id));
        return;
    }
    if (!replaces && existing_state != device::State::Pending) {
        log::debug(
                cat,
                "Ignoring link request from {}: device already in state {}",
                oxenc::to_hex(info.id),
                static_cast<int>(existing_state));
        return;
    }

    SQLite::Transaction tx{c.sql};

    auto dev_id = replaces ? std::optional{std::get<0>(*existing)} : upsert_device_info(c, info);
    if (!dev_id) {
        log::debug(
                cat,
                "Ignoring link request from {}: rejected by seqno guard",
                oxenc::to_hex(info.id));
        return;
    }

    auto sas_seed = derive_sas_seed(std::span<const std::byte>{*plaintext});

    // A newer request from the same device replaces the earlier one for the user's purposes, but
    // does not erase it: the older row stays readable as something this device saw.  Marked before
    // the insert so that exactly one request per device is ever pending.  An ignored one too, since
    // it can still be accepted: accepting it would admit the device under this newer record.
    c.prepared_exec(
            "UPDATE device_link_requests SET status = {} WHERE device = ? AND status IN ({}, {})"_format(
                    static_cast<int>(device::LinkStatus::Superseded),
                    static_cast<int>(device::LinkStatus::Pending),
                    static_cast<int>(device::LinkStatus::Ignored)),
            *dev_id);

    c.prepared_exec(
            R"(INSERT INTO device_link_requests
                (device, received_at, expires_at, sas_seed, hash, info, replaces)
               VALUES (?, ?, ?, ?, ?, ?, ?))",
            *dev_id,
            epoch_seconds(clock_now_s()),
            epoch_seconds(expiry),
            sas_seed,
            hash,
            to_span<std::byte>(raw),
            replaces ? 1 : 0);

    tx.commit();
}

int Devices::_reqid_for(int64_t row) {
    assert(on_loop());
    auto [it, inserted] = _reqid_by_row.try_emplace(row, _next_reqid);
    if (inserted)
        _row_by_reqid.emplace(_next_reqid++, row);
    return it->second;
}

std::optional<int64_t> Devices::_row_for(int reqid) {
    assert(on_loop());
    if (auto it = _row_by_reqid.find(reqid); it != _row_by_reqid.end())
        return it->second;
    return std::nullopt;
}

std::vector<device::LinkRequest> Devices::_link_requests(bool pending_only) {
    auto now = clock_now();
    bool opened = false;
    std::vector<device::LinkRequest> out;
    for (auto& [row, request] : _read_link_requests(pending_only)) {
        if (!_reqid_by_row.contains(row)) {
            // One handed out already closed is seen to be closed; reporting it so would be news
            // about something that happened before the caller ever heard of it.
            if (request.status != device::LinkStatus::Pending || request.expired(now))
                _ended.insert(row);
            else
                opened = true;
        }
        request.id = _reqid_for(row);
        out.push_back(std::move(request));
    }
    // Its deadline is one the expiry timer was not armed for.
    if (opened)
        jq().wake(_expiry_timer);
    return out;
}

std::vector<std::pair<int64_t, device::LinkRequest>> Devices::_read_link_requests(
        bool pending_only) {
    assert(on_loop());
    auto c = conn();
    std::vector<std::pair<int64_t, device::LinkRequest>> out;

    for (auto [row, received, expires, status, sas_seed, record, replaces, devid] :
         c.prepared_results<
                 int64_t,
                 int64_t,
                 int64_t,
                 int,
                 sqlite::blob_guts<std::array<std::byte, 16>>,
                 sqlite::blob,
                 int,
                 sqlite::blob_guts<device::Id>>(
                 "SELECT r.id, r.received_at, r.expires_at, r.status, r.sas_seed, r.info,"
                 "       r.replaces, d.unique_id"
                 "  FROM device_link_requests r JOIN devices d ON d.id = r.device"
                 " WHERE ? = 0 OR (r.status = {} AND r.expires_at > ?)"
                 " ORDER BY r.id DESC"_format(static_cast<int>(device::LinkStatus::Pending)),
                 pending_only ? 1 : 0,
                 epoch_seconds(clock_now_s()))) {
        std::optional<device::Info> current;
        if (replaces) {
            auto held = devices(true, true, true, devid);
            if (auto it = held.find(devid); it != held.end())
                current = std::move(it->second);
        }

        out.emplace_back(
                row,
                device::LinkRequest{
                        .id = 0,
                        .device = requested_record(devid, record),
                        .replaces = std::move(current),
                        .sas = sas_from_seed(sas_seed),
                        .received = std::chrono::sys_seconds{std::chrono::seconds{received}},
                        .expires = std::chrono::sys_seconds{std::chrono::seconds{expires}},
                        .status = static_cast<device::LinkStatus>(status)});
    }
    return out;
}

void Devices::link_requests(result_function<std::vector<device::LinkRequest>> cb) {
    async([this] { return _link_requests(false); }, std::move(cb));
}

std::vector<device::LinkRequest> Devices::link_requests(await_t) {
    return jq().call_get([this] { return _link_requests(false); });
}

void Devices::incoming_link_requests(result_function<std::vector<device::LinkRequest>> cb) {
    async([this] { return _link_requests(true); }, std::move(cb));
}

std::vector<device::LinkRequest> Devices::incoming_link_requests(await_t) {
    return jq().call_get([this] { return _link_requests(true); });
}

void Devices::accept_request(int reqid, result_function<bool> cb) {
    async([this, reqid] { return _accept_request(reqid); }, std::move(cb));
}

bool Devices::accept_request(int reqid, await_t) {
    return jq().call_get([this, reqid] { return _accept_request(reqid); });
}

bool Devices::_accept_request(int reqid) {
    assert(on_loop());
    auto row = _row_for(reqid);
    if (!row)
        throw std::invalid_argument{"accept_request: no such link request in this session"};

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    // A device outside the group has nobody to admit anyone to.  Checked here rather than left to
    // the push, which would simply never happen and leave the request looking accepted.
    if (!_member())
        return false;

    // Ignored too: ignoring is this device's alone, and an Ignore pressed by mistake is put right
    // by accepting after all, for as long as the request is live.
    auto request = c.prepared_maybe_get<int64_t, int>(
            "SELECT device, replaces FROM device_link_requests"
            " WHERE id = ? AND status IN ({}, {}) AND expires_at > ?"_format(
                    static_cast<int>(device::LinkStatus::Pending),
                    static_cast<int>(device::LinkStatus::Ignored)),
            *row,
            epoch_seconds(clock_now_s()));
    if (!request)
        return false;
    auto [dev, replaces] = *request;

    // A new device only from Pending: one kicked since the request arrived is gone for good, and
    // the rank rule would refuse to lower it anyway.
    bool admitted = replaces ? _replace_record(*row)
                             : c.prepared_maybe_get<int64_t>(
                                        "UPDATE devices SET state = ?,"
                                        " broadcast_needed = broadcast_needed + 1"
                                        " WHERE id = ? AND state = ? RETURNING id",
                                        static_cast<int>(device::State::Registered),
                                        dev,
                                        static_cast<int>(device::State::Pending))
                                       .has_value();
    if (!admitted)
        return false;

    c.prepared_exec(
            "UPDATE device_link_requests SET status = ? WHERE id = ?",
            static_cast<int>(device::LinkStatus::Accepted),
            *row);

    tx.commit();

    _ended.insert(*row);
    _devices_changed = true;
    _flush_events();
    _push_soon();
    return true;
}

bool Devices::_replace_record(int64_t row) {
    assert(on_loop());
    auto c = conn();
    std::optional<device::Info> info;
    for (auto [record, id, seqno] :
         c.prepared_results<sqlite::blob, sqlite::blob_guts<device::Id>, int64_t>(
                 "SELECT r.info, d.unique_id, d.seqno"
                 "  FROM device_link_requests r JOIN devices d ON d.id = r.device"
                 " WHERE r.id = ? AND d.state = ?",
                 row,
                 static_cast<int>(device::State::Registered))) {
        info = requested_record(id, record);
        // Above both, so that the record wins every merge: the one it replaces everywhere it is
        // held, and the requesting device's own row, which may have fallen behind with whatever
        // else it lost.
        info->seqno = std::max(seqno, info->seqno) + 1;
    }
    if (!info)
        return false;

    info->state = device::State::Registered;
    info->digest = record_digest(*info);
    auto dev = upsert_device_info(c, *info);
    assert(dev);
    c.prepared_exec(
            "UPDATE devices SET broadcast_needed = broadcast_needed + 1 WHERE id = ?", *dev);

    log::info(cat, "Replacing the record of device {}; rotating the account key", info->id);
    rotate_account_keys();
    return true;
}

void Devices::ignore_request(int reqid, result_function<bool> cb) {
    ignore_request(reqid, false, std::move(cb));
}

void Devices::ignore_request(int reqid, bool delete_from_swarm, result_function<bool> cb) {
    async([this, reqid, delete_from_swarm] { return _ignore_request(reqid, delete_from_swarm); },
          std::move(cb));
}

bool Devices::ignore_request(int reqid, await_t) {
    return ignore_request(reqid, false, await);
}

bool Devices::ignore_request(int reqid, bool delete_from_swarm, await_t) {
    return jq().call_get(
            [this, reqid, delete_from_swarm] { return _ignore_request(reqid, delete_from_swarm); });
}

bool Devices::_ignore_request(int reqid, bool delete_from_swarm) {
    assert(on_loop());
    auto row = _row_for(reqid);
    if (!row)
        throw std::invalid_argument{"ignore_request: no such link request in this session"};

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    auto ignored = c.prepared_maybe_get<std::string>(
            "UPDATE device_link_requests SET status = ? WHERE id = ? AND status = ?"
            " RETURNING hash",
            static_cast<int>(device::LinkStatus::Ignored),
            *row,
            static_cast<int>(device::LinkStatus::Pending));
    if (!ignored)
        return false;

    // The device row stays Pending, deliberately: a redelivery of the same request then fails the
    // merge guard and does not prompt again, while a genuine retry carries a higher seqno and does.
    tx.commit();

    _ended.insert(*row);

    if (delete_from_swarm)
        _delete_from_swarm({std::move(*ignored)}, "an ignored link request");
    return true;
}

void Devices::membership(result_function<device::MembershipState> cb) {
    async([this] { return _membership(); }, std::move(cb));
}

device::MembershipState Devices::membership(await_t) {
    return jq().call_get([this] { return _membership(); });
}

device::MembershipState Devices::_membership() {
    assert(on_loop());
    device::MembershipState out{.membership = device::Membership::Unknown};
    auto c = conn();

    // A group this device was removed, displaced or dropped from is one it can ask to join again,
    // under a new identity, so it is among the others; only a member in good standing has a group.
    if (_member())
        out.group = _group_id();

    for (auto [group, seen] :
         c.prepared_results<sqlite::blob_guts<std::array<std::byte, 8>>, int64_t>(
                 "SELECT group_id, seen_at FROM device_groups"
                 " WHERE expires_at > ? ORDER BY seen_at DESC",
                 epoch_seconds(clock_now_s()))) {
        if (device::GroupId id{group}; id != out.group)
            out.others.push_back({id, from_epoch_s(seen)});
    }

    auto own = static_cast<device::State>(
            c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", self_id)
                    .value_or(static_cast<int>(device::State::Unregistered)));

    if (!_fetched)
        return out;

    switch (own) {
        case device::State::Kicked: out.membership = device::Membership::Removed; break;
        case device::State::Registered:
            // Another group beside ours is a fork, for the user to settle.  Ours gone beside it is
            // something else: whatever became of our group, the account's group is now the other.
            // None of ours left, with no other group, is a group whose messages have yet to reach
            // the swarm, or expired while every device was away, and our next push restores them.
            out.membership = _displaced()        ? device::Membership::Displaced
                           : _dropped()          ? device::Membership::Dropped
                           : !out.others.empty() ? device::Membership::Forked
                                                 : device::Membership::InGroup;
            break;
        default: {
            // Approved even after the request lapsed here, and so was withdrawn: the approval came
            // in time, if its message reached us later.
            auto newest = _newest_request();
            out.membership = newest && newest->held        ? device::Membership::Approved
                           : own == device::State::Pending ? device::Membership::Requesting
                           : core.globals.get_integer(dissolved_key) ? device::Membership::Dissolved
                           : out.others.empty()                      ? device::Membership::NoGroup
                                                : device::Membership::DeviceGroupVisible;
        }
    }
    return out;
}

void Devices::_rebaseline_membership() {
    if (auto state = _membership(); state.membership != device::Membership::Unknown)
        _take_as_reported(state);
}

bool Devices::_take_as_reported(const device::MembershipState& state) {
    std::vector<device::GroupId> others;
    for (const auto& g : state.others)
        others.push_back(g.id);
    std::ranges::sort(others, {}, &device::GroupId::value);
    if (state.membership == _reported_membership && others == _reported_others)
        return false;
    _reported_membership = state.membership;
    _reported_others = std::move(others);
    return true;
}

void Devices::_forget_group() {
    assert(on_loop());
    auto c = conn();
    // Its devices, ourselves included: a group started from these would carry them over as members,
    // and a group joined says who is in it.  Its account keys, which never carry into another group
    // -- a group joined brings its own, and a group started mints a fresh one.  Not the groups it
    // has seen dissolved, which stay dissolved whatever group this device is in.
    c.prepared_exec("DELETE FROM devices");
    c.prepared_exec("DELETE FROM device_group_merged");
    c.prepared_exec("DELETE FROM device_account_keys");
    core.globals.erase(group_id_key);
    core.globals.erase(read_at_key);
    core.globals.erase(displaced_key);
    core.globals.erase(dropped_key);
    core.globals.erase(dissolved_key);
    core.globals.erase(suspect_pubkeys_key);
}

bool Devices::_displaced() {
    return core.globals.get_integer(displaced_key).has_value();
}

bool Devices::_member() {
    return _registered() && !_dropped();
}

bool Devices::_registered() {
    return !_displaced() && conn().prepared_maybe_get<int>(
                                    "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                                    self_id,
                                    static_cast<int>(device::State::Registered));
}

void Devices::_note_read(sys_ms t) {
    int64_t ms = epoch_ms(t);
    if (auto read_at = core.globals.get_integer(read_at_key); !read_at || ms > *read_at)
        core.globals.set(read_at_key, ms);

    // Read again at or past what displaced or dropped us, which only a member could: the group took
    // us back, or what looked like it had moved on was a snapshot that had yet to hear of us.
    for (auto key : {displaced_key, dropped_key})
        if (auto at = core.globals.get_integer(key); at && ms >= *at) {
            core.globals.erase(key);
            log::info(cat, "This device can read its device group again");
            if (_member())
                _reread_account_pubkeys();
        }
}

bool Devices::_cast_out() {
    return _displaced() || _dropped() ||
           conn().prepared_maybe_get<int>(
                   "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                   self_id,
                   static_cast<int>(device::State::Kicked));
}

void Devices::_new_identity() {
    assert(on_loop());
    // Before the transaction, which it would otherwise nest inside.
    rotate_device_keys();

    device::Id id;
    {
        auto c = conn();
        SQLite::Transaction tx{c.sql};
        id = _forget_identity();
        tx.commit();
    }
    _adopt_identity(id);
}

device::Id Devices::_forget_identity() {
    device::Id id;
    random::fill(id);
    _forget_group();
    core.globals.set(dev_key, std::span<const std::byte>{id});
    _forget_own_requests();
    return id;
}

void Devices::_adopt_identity(const device::Id& id) {
    log::info(cat, "Replaced device id {} with {}", self_id, id);
    self_id = id;
    _reqid_by_row.clear();
    _row_by_reqid.clear();
    _ended.clear();
}

void Devices::start_device_group(
        std::vector<device::GroupId> replacing, result_function<device::GroupId> cb) {
    async([this, replacing = std::move(replacing)] { return _start_device_group(replacing); },
          std::move(cb));
}

device::GroupId Devices::start_device_group(std::vector<device::GroupId> replacing, await_t) {
    return jq().call_get([this, &replacing] { return _start_device_group(replacing); });
}

device::GroupId Devices::_start_device_group(const std::vector<device::GroupId>& replacing) {
    assert(on_loop());
    auto state = _membership();
    bool leaving = false;
    switch (state.membership) {
        case device::Membership::Unknown:
            throw session::error{
                    err::membership_unknown,
                    "Cannot start a group before a fetch has shown what the swarm holds"};
        case device::Membership::InGroup:
        case device::Membership::Forked:
        case device::Membership::Removed:
        case device::Membership::Displaced:
        case device::Membership::Dropped: leaving = true; break;
        case device::Membership::Requesting:
        case device::Membership::Approved:
        case device::Membership::NoGroup:
        case device::Membership::DeviceGroupVisible:
        case device::Membership::Dissolved: break;
    }

    // The account can have only one group, and the user starting this one is choosing it over
    // every one in view, ours included.  Taken from `state`, so that it is what `membership()`
    // lists for an application to show before the call.  Not news to this device, which is making
    // the choice.
    std::vector<device::GroupId> dissolved;
    if (state.group)
        dissolved.push_back(*state.group);
    for (const auto& other : state.others)
        dissolved.push_back(other.id);

    // But only if the user chose it over each of them: one that appeared after they were shown the
    // list is one they never saw, and dissolving it would be dissolving a group nobody chose to.
    // Checked before anything changes, so that the refusal leaves everything as it was.
    if (!std::ranges::all_of(dissolved, [&](const auto& g) {
            return std::ranges::find(replacing, g) != replacing.end();
        }))
        throw session::error{
                err::groups_changed,
                "The device groups in view are not the ones confirmed for replacing"};

    // Leaving whatever group it was in, as any leaving does, under a new id and new device keys.
    if (leaving)
        rotate_device_keys();

    // Committed together, so that a crash cannot leave the groups dissolved under an identity that
    // goes on as theirs, or a new identity with the old group still standing.  The group itself is
    // owed rather than made here, since making it opens transactions of its own; `establish_group`
    // finishes it after a crash as well as now.
    device::Id id;
    {
        auto c = conn();
        SQLite::Transaction tx{c.sql};
        // Our own group's messages too, as a sole member leaving deletes them; only a member in
        // good standing speaks for its group, which is when `state.group` is set.
        if (!dissolved.empty())
            _queue_dissolution(
                    dissolved, state.group ? _merged_hashes() : std::vector<std::string>{});
        if (state.membership == device::Membership::Requesting ||
            state.membership == device::Membership::Approved)
            _withdraw_own_request();

        // Whatever it held before is no group's, the group starts with a fresh key, and an
        // admission on anything it asked before would take it straight back out.
        if (leaving) {
            id = _forget_identity();
        } else {
            _forget_group();
            _forget_own_requests();
        }
        _mark_group_owed();
        tx.commit();
    }
    if (leaving)
        _adopt_identity(id);
    if (!dissolved.empty())
        log::info(cat, "Dissolved {} device group(s) to start a new one", dissolved.size());

    establish_group();
    auto group = _group_id();
    if (!group)
        throw std::logic_error{"Started a group but it has no identifier"};
    log::info(cat, "Started a new device group");

    _send_pending_pushes();
    _reread_account_pubkeys();

    _devices_changed = true;
    _rebaseline_membership();
    _flush_events();
    return *group;
}

void Devices::dissolve_group(device::GroupId group, result_function<bool> cb) {
    async([this, group] { return _dissolve_group(group); }, std::move(cb));
}

bool Devices::dissolve_group(const device::GroupId& group, await_t) {
    return jq().call_get([this, &group] { return _dissolve_group(group); });
}

bool Devices::_dissolve_group(const device::GroupId& group) {
    assert(on_loop());
    if (group == _group_id())
        throw std::invalid_argument{"dissolve_group: cannot dissolve this device's own group"};

    auto state = _membership();
    if (state.membership != device::Membership::Forked ||
        std::ranges::find(state.others, group, &device::VisibleGroup::id) == state.others.end())
        return false;

    _dissolve(std::span{&group, 1});
    _rebaseline_membership();
    _flush_events();
    return true;
}

bool Devices::_dropped() {
    auto ours = _group_id();
    if (!ours)
        return false;
    if (core.globals.get_integer(dropped_key))
        return true;
    auto c = conn();
    auto id = std::span<const std::byte>{ours->value};
    auto now = epoch_seconds(clock_now_s());
    return !c.prepared_maybe_get<int>(
                   "SELECT 1 FROM device_groups WHERE group_id = ? AND expires_at > ?", id, now) &&
           c.prepared_maybe_get<int>(
                   "SELECT 1 FROM device_groups WHERE group_id != ? AND expires_at > ?", id, now);
}

void Devices::remove_device(device::Id id, result_function<bool> cb) {
    async([this, id] { return _remove_device(id); }, std::move(cb));
}

bool Devices::remove_device(std::span<const std::byte, device::ID_SIZE> id, await_t) {
    return jq().call_get([this, id] { return _remove_device(id); });
}

bool Devices::_remove_device(std::span<const std::byte, device::ID_SIZE> id) {
    assert(on_loop());
    if (std::ranges::equal(id, self_id))
        throw std::invalid_argument{"remove_device: cannot remove this device itself"};

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    if (!_member())
        return false;

    if (!c.prepared_maybe_get<int64_t>(
                "UPDATE devices SET state = ?, kicked_timestamp = ?, removed_by_us = 1,"
                " broadcast_needed = broadcast_needed + 1"
                " WHERE unique_id = ? AND state = ? RETURNING id",
                static_cast<int>(device::State::Kicked),
                epoch_seconds(clock_now_s()),
                id,
                static_cast<int>(device::State::Registered)))
        return false;

    // In the same transaction, so there is no moment at which the removal is recorded and the key
    // the removed device holds is still the one a push would treat as current.
    rotate_account_keys();
    _pull_in_device_rotation();
    tx.commit();

    log::info(cat, "Removed device {} from the group", oxenc::to_hex(id));
    _devices_changed = true;
    _flush_events();
    _push_soon();
    return true;
}

void Devices::forget_link_requests(std::vector<int> reqids, result_function<size_t> cb) {
    async([this, reqids = std::move(reqids)] { return _forget_link_requests(reqids); },
          std::move(cb));
}

size_t Devices::forget_link_requests(std::span<const int> reqids, await_t) {
    return jq().call_get([this, reqids] { return _forget_link_requests(reqids); });
}

size_t Devices::_forget_link_requests(std::span<const int> reqids) {
    assert(on_loop());
    std::vector<int64_t> rows;
    for (auto id : reqids)
        if (auto row = _row_for(id))
            rows.push_back(*row);
    if (rows.empty())
        return 0;

    std::vector<int64_t> gone;
    auto c = conn();
    for (auto row : c.prepared_results<int64_t>(
                 "DELETE FROM device_link_requests WHERE id IN ({})"
                 " AND NOT (status = {} AND expires_at > ?) RETURNING id"_format(
                         sqlite::placeholders(rows.size()),
                         static_cast<int>(device::LinkStatus::Pending)),
                 sqlite::bind_each{rows},
                 epoch_seconds(clock_now_s())))
        gone.push_back(row);

    for (auto row : gone) {
        _ended.erase(row);
        if (auto it = _reqid_by_row.find(row); it != _reqid_by_row.end()) {
            _row_by_reqid.erase(it->second);
            _reqid_by_row.erase(it);
        }
    }
    return gone.size();
}

void Devices::_flush_events() {
    assert(on_loop());
    auto now = clock_now_s();

    // Not cleared when we are admitted: the withdrawal finds nothing Pending and does nothing,
    // which is simpler than clearing the deadline on every path that can admit us.
    auto next_deadline = _own_deadline();
    if (next_deadline && *next_deadline <= now) {
        _withdraw_own_request();
        next_deadline.reset();
    }

    bool changed = std::exchange(_devices_changed, false);
    auto members = std::exchange(_member_changes, {});
    if (auto* events = cb().devices)
        if (auto theirs = _report_events(*events, changed, members, now))
            next_deadline = std::min(next_deadline.value_or(*theirs), *theirs);

    _arm_expiry(next_deadline);
}

void Devices::_arm_expiry(std::optional<std::chrono::sys_seconds> deadline) {
    if (!deadline) {
        jq().stop(_expiry_timer);
        return;
    }
    // A non-positive interval would stop the timer instead.  Firing a moment early is harmless:
    // the flush it runs finds nothing expired and re-arms for the remainder.
    auto delay = std::chrono::ceil<std::chrono::microseconds>(*deadline - clock_now());
    jq().repeat(_expiry_timer, std::max<std::chrono::microseconds>(delay, 1ms));
}

std::optional<std::chrono::sys_seconds> Devices::_report_events(
        DeviceEvents& events,
        bool devices_changed,
        std::span<const device::Id> member_changes,
        std::chrono::sys_seconds now) {
    // One handler throwing must not take the others' reports down with it.
    auto report = [](std::string_view which, auto&& call) {
        try {
            call();
        } catch (const std::exception& e) {
            log::error(cat, "DeviceEvents::{} threw: {}", which, e.what());
        }
    };

    auto c = conn();
    std::optional<std::chrono::sys_seconds> next_deadline;
    auto open_until = [&](std::chrono::sys_seconds expires) {
        next_deadline = std::min(next_deadline.value_or(expires), expires);
    };

    // Closed before opened, so a request superseded by a resend has its prompt closed before the
    // new one's is raised.
    std::vector<std::pair<int, device::LinkRequestEnd>> ended;
    for (const auto& [row, reqid] : _reqid_by_row) {
        if (_ended.contains(row))
            continue;
        auto st = c.prepared_maybe_get<int, int64_t>(
                "SELECT status, expires_at FROM device_link_requests WHERE id = ?", row);
        if (!st) {
            _ended.insert(row);
            continue;
        }
        auto [status, expires] = *st;
        std::optional<device::LinkRequestEnd> why;
        switch (static_cast<device::LinkStatus>(status)) {
            case device::LinkStatus::Accepted: why = device::LinkRequestEnd::Accepted; break;
            case device::LinkStatus::Superseded: why = device::LinkRequestEnd::Superseded; break;
            case device::LinkStatus::Ignored: _ended.insert(row); break;
            case device::LinkStatus::Pending:
                if (from_epoch_s(expires) <= now)
                    why = device::LinkRequestEnd::Expired;
                else
                    open_until(from_epoch_s(expires));
                break;
        }
        if (why) {
            _ended.insert(row);
            ended.emplace_back(reqid, *why);
        }
    }
    for (auto [reqid, why] : ended)
        report("link_request_ended", [&] { events.link_request_ended(reqid, why); });

    // Only once the swarm has been asked: a request stored before a restart may have been
    // answered or expired while we were away, and the fetch is what says so.
    if (_fetched)
        for (auto& [row, request] : _read_link_requests(true))
            if (!_reqid_by_row.contains(row)) {
                request.id = _reqid_for(row);
                open_until(request.expires);
                report("link_request_added",
                       [&] { events.link_request_added(std::move(request)); });
            }

    // Each as it stands now, which is what it changed to: a device admitted and removed again
    // within one fetch reads as removed, which is the news.
    for (const auto& id : member_changes)
        for (auto& [_, info] : devices(true, false, true, id))
            report("device_membership_changed",
                   [&] { events.device_membership_changed(std::move(info)); });

    if (devices_changed)
        report("devices_replaced", [&] { events.devices_replaced(devices(true, false, true)); });

    auto state = _membership();
    if (state.membership != device::Membership::Unknown && _take_as_reported(state))
        report("membership_changed", [&] { events.membership_changed(state.membership); });

    return next_deadline;
}

void Devices::parse_device_messages(std::span<const SwarmMessage> messages, bool is_final) {
    for (const auto& msg : messages) {
        try {
            oxenc::bt_dict_consumer in{msg.data};
            auto type = in.require<std::string_view>("");
            if (type == "G") {
                if (_record_group(msg))
                    receive_device_group_message(msg.data, msg.hash);
            } else if (type == "L")
                receive_link_request(msg.data, msg.hash, msg.expiry);
            else if (type == "T")
                receive_dissolution(msg.data);
            else
                log::warning(cat, "Ignoring device message with unknown type '{}'", type);
        } catch (const std::exception& e) {
            log::warning(cat, "Ignoring malformed device message: {}", e.what());
        }
    }

    if (!is_final)
        return;

    _fetched = true;
    _flush_events();

    // Rotated here, after the fetch, and not before it: what waited for us in the swarm was
    // encrypted to the keys we had, and a device back from a long absence rotates once, now.
    _rotate_due_keys();

    // This fetch is the retry of any push that failed, made just below.
    _push_retry_at.reset();
    _arm_fetch_timer();

    // Pushed from here rather than from whatever dirtied the group, so that what goes out is built
    // on top of everything this fetch merged.  A local change made between fetches waits for the
    // next one, which is what stops two devices answering the same update with duelling pushes.
    push_owed();
    _send_pending_pushes();

    // Keys seen on -21 whose fetch failed, or that were waiting across a restart -- unless this
    // device is no longer a member: whatever it lost good standing to, it has no keys to judge them
    // by now, and one it held while away could be rotated out of reach by the time it is back.
    if (_member())
        _verify_suspects();
    else
        core.globals.erase(suspect_pubkeys_key);
}

void Devices::parse_account_pubkeys(std::span<const SwarmMessage> messages, bool /*is_final*/) {
    if (messages.empty())
        return;

    // The x25519 pubkey for signature verification: session_id() is 0x05 || x25519_pub
    auto x25519_pub = core.globals.session_id().subspan<1>();

    // Only a member in good standing judges what -21 holds.  A device outside the group holds none
    // of its keys, or stale ones, so every key of its group would look like none of the account's;
    // it reads -21 again from the start once it is a member (see `_reread_account_pubkeys`).
    bool member = _member();

    for (const auto& msg : messages) {
        try {
            oxenc::bt_dict_consumer in{msg.data};
            auto M = in.require_span<std::byte, mlkem768::PUBLICKEYBYTES>("M");
            auto X = in.require_span<std::byte, 32>("X");
            in.require_signature(
                    "~",
                    [&x25519_pub](std::span<const std::byte> body, std::span<const std::byte> sig) {
                        if (sig.size() != 64 ||
                            !xed25519::verify(sig.first<64>(), x25519_pub, body))
                            throw std::runtime_error{
                                    "Invalid account pubkey message: signature verification "
                                    "failed"};
                    });

            if (_mark_published(M, X) || !member)
                continue;

            // Not ours, as far as we know yet.  Whatever PFS/PQ says: a seed holder publishing a
            // key need not have enabled it, and contacts encrypt to whatever they find.
            log::info(cat, "Namespace -21 holds an account key we do not know of; checking it");
            auto held =
                    core.globals.get_blob(suspect_pubkeys_key).value_or(std::vector<std::byte>{});
            held.insert(held.end(), X.begin(), X.end());
            held.insert(held.end(), M.begin(), M.end());
            core.globals.set(suspect_pubkeys_key, std::span<const std::byte>{held});
        } catch (const std::exception& e) {
            log::warning(cat, "Ignoring malformed account pubkey message: {}", e.what());
        }
    }
    _verify_suspects();
}

void Devices::_verify_suspects() {
    if (!core.network() || !core.globals.get_blob(suspect_pubkeys_key))
        return;
    std::vector namespaces{config::Namespace::Devices};
    // A fetch already under way may have read 21 before the group message that makes the key ours
    // reached the swarm: only one sent after the key was seen can settle it.
    bool joined = core._fetches.contains(namespaces);
    core._fetch(
            std::move(namespaces),
            [this, alive = std::weak_ptr<int>{_alive}, joined](bool fetched) {
                // A failed one leaves them waiting for the next fetch to complete.
                if (alive.expired() || !fetched)
                    return;
                if (joined)
                    _verify_suspects();
                else
                    _judge_suspects();
            });
}

void Devices::_reread_account_pubkeys() {
    // Forgetting the cursor is what makes the next read of -21 a full one: it would otherwise
    // resume past whatever -21 held before now, and a key published before this device could judge
    // it -- a rogue one included -- would never be judged.
    conn().prepared_exec(
            "DELETE FROM swarm_hashes WHERE namespace = ?",
            static_cast<int16_t>(config::Namespace::AccountPubkeys));

    // And the fetch is what makes there be a next read: a device subscribed for pushes does not
    // poll, and -21 sends it nothing until something new lands there.  Without a network the first
    // poll once one is attached reads it.
    if (core.network())
        core._fetch({config::Namespace::AccountPubkeys}, nullptr);
}

void Devices::_judge_suspects() {
    auto held = core.globals.get_blob(suspect_pubkeys_key);
    if (!held)
        return;
    core.globals.erase(suspect_pubkeys_key);

    // No longer a member, so no longer holding the keys to judge them by; read again on rejoining.
    if (!_member())
        return;

    constexpr size_t X_SIZE = 32, M_SIZE = mlkem768::PUBLICKEYBYTES;
    bool rogue = false;
    for (size_t i = 0; i + X_SIZE + M_SIZE <= held->size(); i += X_SIZE + M_SIZE) {
        auto X = std::span<const std::byte, X_SIZE>{held->data() + i, X_SIZE};
        auto M = std::span<const std::byte, M_SIZE>{held->data() + i + X_SIZE, M_SIZE};
        // Known now: another device's rotation, whose group message has since arrived.
        if (!_mark_published(M, X))
            rogue = true;
    }
    if (!rogue)
        return;

    log::warning(
            cat,
            "Namespace -21 holds an account key that is none of ours: someone else holds the "
            "account seed");

    // Where the account publishes its key, ours goes back over it; nothing is deleted from -21,
    // which a seed holder could only publish to again.
    if (core._pfs_enabled())
        conn().prepared_exec("UPDATE device_account_keys SET published = 0 WHERE rotated IS NULL");

    if (cb().rogue_account_key) {
        try {
            cb().rogue_account_key();
        } catch (const std::exception& e) {
            log::error(cat, "rogue_account_key callback threw: {}", e.what());
        }
    }

    // A fetch has just completed, which is all a push waits on.
    push_owed();
}

bool Devices::_mark_published(
        std::span<const std::byte, 1184> mlkem768_pub, std::span<const std::byte, 32> x25519_pub) {
    // By indicator first, which is indexed, then the whole of both halves: a message carrying our
    // X25519 key beside an ML-KEM key that is not ours is not our key.
    auto current = conn().prepared_maybe_get<int>(
            "UPDATE device_account_keys SET published = 1"
            " WHERE key_indicator = ? AND pubkey_mlkem768 = ? AND pubkey_x25519 = ?"
            " RETURNING rotated IS NULL",
            mlkem768_pub.first<2>(),
            mlkem768_pub,
            x25519_pub);
    if (!current)
        return false;

    // The current key on -21 is exactly what a lookup of our own session id would find, so every
    // device that sees it, not only the one that published it, sends its copies of what it sends
    // to it at once.  A rotated-away one says nothing about what to encrypt to.
    if (*current)
        core._cache_own_pfs_key(x25519_pub, mlkem768_pub);
    return true;
}

static const std::string NEEDS_PUSH_SQL =
        "SELECT"
        // registered
        " EXISTS(SELECT 1 FROM devices WHERE unique_id = ? AND state = {0}),"
        // something other than our own record owed: a state transition, or an undistributed key
        " EXISTS(SELECT 1 FROM devices WHERE broadcast_needed)"
        "   OR EXISTS(SELECT 1 FROM device_account_keys WHERE NOT distributed),"
        // account_pubkey: the current active account key has not yet been confirmed on the swarm
        " EXISTS(SELECT 1 FROM device_account_keys WHERE rotated IS NULL AND NOT published)"_format(
                static_cast<int>(device::State::Registered));

Devices::NeedsPush Devices::needs_push() {
    auto c = conn();
    auto [registered, owed, ap] = c.prepared_get<int, int, int>(NEEDS_PUSH_SQL, self_id);
    // Not for a group that has moved on without us: we cannot read what it holds now, and would
    // push a snapshot of what it held before.  Nor for one gone from the swarm while another is
    // there: pushing would bring it back beside the one the account now has.
    bool member = registered && !_displaced() && !_dropped();
    bool dg = member && (owed || _own_record().seqno != _held_record()->seqno);
    // Publishing the key is what has contacts send PFS/PQ messages, so only once every device of
    // the account has been declared able to read them -- and, as for rotating it, only by a member
    // in good standing, which is what keeps the key current.
    // The public form, since this is called from other threads too and the config lives on the
    // loop.
    return {.device_group = dg, .account_pubkey = member && ap && core.pfs_enabled()};
}

void Devices::mark_device_group_pushed(const DeviceGroupPush& push, std::string hash) {
    auto c = conn();
    SQLite::Transaction tx{c.sql};

    // What the swarm now holds for us.  Rank-guarded like any merge, so a record that has
    // overtaken it meanwhile -- a forged one, say -- stays, and our next push overtakes that in
    // turn.
    if (upsert_device_info(c, push.own))
        _devices_changed = true;

    // Our own group, seen as it now is in the swarm -- its link key included -- without waiting for
    // the next fetch to bring the message back.
    _record_group(
            {.data = push.message,
             .hash = hash,
             .expiry = clock_now_ms() +
                       std::chrono::duration_cast<std::chrono::milliseconds>(DEVICE_GROUP_TTL)});

    // Gone from the swarm, so stop naming them.  Scoped to what this message carried: one merged
    // while the push was in flight was not deleted and is not superseded by it.
    if (!push.obsolete.empty())
        for (auto table : {"device_group_merged"sv, "device_group_messages"sv})
            c.prepared_exec(
                    "DELETE FROM {} WHERE hash IN ({})"_format(
                            table, sqlite::placeholders(push.obsolete.size())),
                    sqlite::bind_each{push.obsolete});

    // Our own message is now the newest snapshot, and the next push supersedes it in turn -- by the
    // same rule as everyone else's, since what makes a snapshot redundant is that its contents have
    // been carried forward, not who wrote it.
    if (!hash.empty())
        c.prepared_exec(
                "INSERT INTO device_group_merged (hash) VALUES (?) ON CONFLICT DO NOTHING", hash);

    for (const auto& [id, generation] : push.broadcast)
        c.prepared_exec(
                "UPDATE devices SET broadcast_needed = 0"
                " WHERE unique_id = ? AND broadcast_needed = ?",
                id,
                generation);

    if (!push.keys.empty())
        c.prepared_exec(
                "UPDATE device_account_keys SET distributed = 1 WHERE id IN ({})"_format(
                        sqlite::placeholders(push.keys.size())),
                sqlite::bind_each{push.keys});
    _record_key_delivery(push.carried_keys, push.recipients);

    tx.commit();
}

void Devices::push_owed() {
    if (_push_in_flight)
        return;
    auto owed = needs_push();

    std::optional<DeviceGroupPush> group;
    if (owed.device_group) {
        try {
            group = build_device_group_message();
        } catch (const std::exception& e) {
            log::warning(cat, "Not pushing device group: {}", e.what());
        }
    }

    struct Pubkey {
        std::array<std::byte, 1184> mlkem768;
        std::array<std::byte, 32> x25519;
    };
    std::optional<Pubkey> pubkey;
    if (owed.account_pubkey) {
        auto current = active_account_keys().front();
        pubkey = Pubkey{current.mlkem768_pub, current.x25519_pub};
    }

    if (!group && !pubkey)
        return;

    // Index-aligned with the results: the group message first, when there is one.
    std::vector<SwarmStore> stores;
    if (group)
        stores.push_back(
                {.ns = config::Namespace::Devices,
                 .data = group->message,
                 .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(DEVICE_GROUP_TTL)});
    if (pubkey)
        stores.push_back(
                {.ns = config::Namespace::AccountPubkeys,
                 .data = _account_pubkey_message(pubkey->mlkem768, pubkey->x25519),
                 .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(ACCOUNT_PUBKEY_TTL)});

    _push_in_flight = true;

    // Copied out before the call rather than passed as `group->obsolete`: the callback below
    // captures `group` by move, and the order the two arguments are evaluated in is unspecified, so
    // reading it inline can hand over an empty list from an already-moved-from struct.  Nothing to
    // delete for -21, which holds one message and replaces it with each store.
    auto obsolete = group ? group->obsolete : std::vector<std::string>{};

    core._swarm_push(
            std::move(stores),
            std::move(obsolete),
            [this, alive = std::weak_ptr<int>{_alive}, group = std::move(group), pubkey](
                    std::optional<std::vector<SwarmStoreResult>> results) {
                if (alive.expired())
                    return;
                _push_in_flight = false;

                size_t next = 0;
                auto stored = [&]() -> SwarmStoreResult* {
                    auto i = next++;
                    return results && i < results->size() && (*results)[i].stored ? &(*results)[i]
                                                                                  : nullptr;
                };
                bool failed = false;
                if (group) {
                    if (auto* r = stored())
                        mark_device_group_pushed(*group, std::move(r->hash));
                    else
                        failed = true;
                }
                if (pubkey) {
                    if (stored())
                        _mark_published(pubkey->mlkem768, pubkey->x25519);
                    else
                        failed = true;
                }

                if (failed) {
                    log::warning(cat, "Device group push was not stored in full; will retry");
                    _push_failed();
                    return;
                }

                _push_stored();

                // A change made while this was in flight found it so and was not pushed; with this
                // confirmed, nothing else owes it a fetch -- a subscribed device does not poll --
                // so ask for the one its push follows.
                _push_soon();
            });
}

std::optional<Devices::RotationBasis> Devices::_rotation_basis() {
    auto c = conn();
    SQLite::Transaction tx{c.sql};

    if (!_member())
        return std::nullopt;

    std::optional<RotationBasis> basis;
    for (auto [id, created, seed] : c.prepared_results<int64_t, int64_t, sqlite::blobn<32>>(
                 "SELECT id, created, seed FROM device_account_keys"
                 " WHERE rotated IS NULL ORDER BY created DESC LIMIT 1")) {
        auto& b = basis.emplace();
        b.key_id = id;
        b.created = std::chrono::sys_seconds{std::chrono::seconds{created}};
        std::memcpy(b.seed.data(), seed.data(), seed.size());
    }
    if (!basis)
        return std::nullopt;

    for (auto id : c.prepared_results<sqlite::blob_guts<device::Id>>(
                 "SELECT unique_id FROM devices WHERE state = ?",
                 static_cast<int>(device::State::Registered)))
        basis->registered.push_back(id);

    tx.commit();
    return basis;
}

std::chrono::system_clock::time_point Devices::_rotation_slot(
        const RotationBasis& basis, const device::Id& device) {
    // u is a per-device uniform random value in [0,1], derived deterministically from the device
    // ID and current account key seed so that each device independently computes a consistent
    // rotation schedule.
    std::array<std::byte, 8> hash_out;
    hash::blake2b_key_pers(hash_out, basis.seed, PERS_ACC_KEY_ROT, device);
    double u = oxenc::load_little_to_host<uint64_t>(hash_out.data()) / 0x1p64;

    // With N registered devices, the minimum of their N individual offsets is uniformly
    // distributed in [PERIOD - JITTER/2, PERIOD + JITTER/2].
    auto N = static_cast<double>(basis.registered.size());
    auto offset = std::chrono::duration_cast<std::chrono::system_clock::duration>(
            (KEY_ROTATION_PERIOD - KEY_ROTATION_JITTER / 2) +
            KEY_ROTATION_JITTER * (1.0 - std::pow(u, N)));
    return basis.created + offset;
}

std::optional<std::chrono::system_clock::time_point> Devices::next_account_rotation() {
    auto basis = _rotation_basis();
    if (!basis)
        return std::nullopt;
    auto scheduled = _rotation_slot(*basis, self_id);
    if (auto early = _early_account_rotation(basis->key_id))
        return std::min(scheduled, std::chrono::system_clock::time_point{*early});
    return scheduled;
}

std::vector<std::pair<device::Id, std::chrono::system_clock::time_point>>
Devices::account_rotation_schedule() {
    std::vector<std::pair<device::Id, std::chrono::system_clock::time_point>> out;
    auto basis = _rotation_basis();
    if (!basis)
        return out;
    for (const auto& device : basis->registered)
        out.emplace_back(device, _rotation_slot(*basis, device));
    std::ranges::sort(out, {}, &decltype(out)::value_type::second);
    return out;
}

std::optional<std::chrono::system_clock::time_point> Devices::scheduled_account_rotation() {
    auto schedule = account_rotation_schedule();
    if (schedule.empty())
        return std::nullopt;
    return schedule.front().second;
}

std::optional<sys_ms> Devices::_early_account_rotation(int64_t key) {
    if (!_key_held_outside(key)) {
        core.globals.erase(early_rotation_key);
        return std::nullopt;
    }
    if (auto at = core.globals.get_integer(early_rotation_key))
        return from_epoch_ms(*at);

    auto at = clock_now_ms();
    if (!_key_held_outside(key, true))
        at += jitter();
    core.globals.set(early_rotation_key, epoch_ms(at));
    log::info(cat, "The account key reached a device no longer in the group; replacing it early");
    return at;
}

void Devices::_pull_in_device_rotation() {
    auto at = clock_now_ms() + jitter();
    auto due = core.globals.get_integer(device_rotation_key);
    if (!due || epoch_ms(at) < *due)
        core.globals.set(device_rotation_key, epoch_ms(at));
}

std::optional<std::chrono::system_clock::time_point> Devices::next_device_rotation() {
    if (!_member())
        return std::nullopt;
    if (auto due = core.globals.get_integer(device_rotation_key))
        return from_epoch_ms(*due);

    // Keys made before their rotation was scheduled with them.
    auto created = conn().prepared_maybe_get<int64_t>(
            "SELECT created FROM device_privkeys WHERE rotated IS NULL");
    if (!created)
        return std::nullopt;
    return _schedule_device_rotation(from_epoch_s(*created));
}

void Devices::_rotate_due_keys() {
    assert(on_loop());
    if (!_member())
        return;
    if (account_rotation_due()) {
        log::info(cat, "Account key rotation is due");
        rotate_account_keys();
    }
    if (device_rotation_due()) {
        log::info(cat, "Device key rotation is due");
        rotate_device_keys();
    }
}

void Devices::_push_soon() {
    // A fetch rather than the push itself: a push goes out only on top of what the swarm holds,
    // which is what stops two devices answering the same update with duelling pushes.
    if (!core.network())
        return;
    if (auto owed = needs_push(); owed.device_group || owed.account_pubkey)
        core._fetch({config::Namespace::Devices}, nullptr);
}

void Devices::_arm_fetch_timer() {
    std::optional<std::chrono::system_clock::time_point> next;
    auto consider = [&next](std::optional<std::chrono::system_clock::time_point> t) {
        if (t && (!next || *t < *next))
            next = t;
    };
    consider(next_account_rotation());
    consider(next_device_rotation());
    consider(_push_retry_at);
    if (!next) {
        jq().stop(_fetch_timer);
        return;
    }
    auto delay = std::chrono::ceil<std::chrono::microseconds>(*next - clock_now());
    jq().repeat(_fetch_timer, std::max<std::chrono::microseconds>(delay, 1ms));
}

void Devices::_push_failed() {
    // A device subscribed for pushes has stopped polling, so nothing else would fetch again -- and
    // a push goes out only after a fetch -- until another device happened to push, or the
    // application restarted: what failed would stay owed for as long as that took.
    if (!_push_retry_at) {
        _push_retry_at = clock_now_ms() + _push_backoff;
        _push_backoff = std::min(_push_backoff * 2, PUSH_RETRY_MAX);
    }
    _arm_fetch_timer();
}

void Devices::_push_stored() {
    _push_backoff = PUSH_RETRY_FIRST;
}

Devices::DeviceGroupPush Devices::build_device_group_message() {
    auto devs = devices(true, true, true);

    auto self = devs.find(self_id);
    if (self == devs.end() || self->second.state != device::State::Registered)
        throw std::logic_error{"Cannot build device group message: this device is not registered"};

    // Ours as we publish it, not as the group holds it: the group's copy only says what reached
    // the swarm, and is never what we take ours from.
    DeviceGroupPush push;
    push.own = _own_record();
    self->second = push.own;

    // Read in the same breath as the payload, so that what the confirm clears is what the message
    // actually contains rather than whatever is owed by the time the swarm answers.
    auto c = conn();
    for (auto [id, generation] : c.prepared_results<sqlite::blob_guts<device::Id>, int64_t>(
                 "SELECT unique_id, broadcast_needed FROM devices WHERE broadcast_needed"))
        push.broadcast.emplace_back(id, generation);
    for (auto [id, distributed] :
         c.prepared_results<int64_t, int>("SELECT id, distributed FROM device_account_keys")) {
        push.carried_keys.push_back(id);
        if (!distributed)
            push.keys.push_back(id);
    }
    for (const auto& [id, info] : devs)
        if (info.state == device::State::Registered)
            push.recipients.push_back(id);
    push.obsolete = _merged_hashes();

    push.message = encrypt_device_data(devs);
    return push;
}

std::vector<std::byte> Devices::build_account_pubkey_message() {
    auto keys = active_account_keys();
    if (keys.empty())
        throw std::runtime_error{"build_account_pubkey_message: no active account keys"};
    return _account_pubkey_message(keys.front().mlkem768_pub, keys.front().x25519_pub);
}

std::vector<std::byte> Devices::_account_pubkey_message(
        std::span<const std::byte, 1184> mlkem768_pub, std::span<const std::byte, 32> x25519_pub) {
    std::vector<std::byte> out(
            2                             // outer dict d...e
            + 3 + bt_bytes_encoded(1184)  // "1:M" + mlkem768_pub
            + 3 + bt_bytes_encoded(32)    // "1:X" + x25519_pub
            + 3 + bt_bytes_encoded(64)    // "1:~" + XEd25519 signature
    );

    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};
    o.append("M", mlkem768_pub);
    o.append("X", x25519_pub);
    o.append_signature("~", [seed = core.globals.account_seed()](std::span<const std::byte> body) {
        return xed25519::sign(seed.x25519_key(), body);
    });

    assert(o.view().size() == out.size());  // Ensure we calculated exactly the right size above
    return out;
}

}  // namespace session::core
