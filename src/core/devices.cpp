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

// The swarm timestamp of the newest message from our group that we could read, and of the one we
// could not that displaced us from it, in unix milliseconds.
static constexpr auto read_at_key = "devices_group_read_at"sv;
static constexpr auto displaced_key = "devices_group_displaced_at"sv;

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

    // A request of ours from the last run carries on if the swarm still holds it, or if an
    // admission on it waits for the user.  Otherwise it is withdrawn: lapsed, or never confirmed
    // stored, which leaves us Pending with nothing to wait on.  Withdrawn only here -- a copy that
    // did reach the swarm can still be accepted, and admits us once the user confirms it.
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

    // `broadcast_needed` rather than a bumped seqno is what marks this for pushing: seqno tracks
    // changes to our *info*, and nothing about our info has changed -- we have gone from being no
    // device at all to being a registered one, which is a state transition.
    //
    // The descriptive fields are left empty deliberately.  An application sets them through
    // update_info() whenever it gets around to it, and that bumps the seqno normally; a group whose
    // sole device has no description is honest about what we know, where inventing one would not
    // be.
    c.prepared_exec(
            R"(INSERT INTO devices
                (unique_id, state, seqno, timestamp, device_type, description, version,
                 pubkey_mlkem768, pubkey_x25519, broadcast_needed)
               VALUES (?1, ?2, 1, ?3, '', '', 0, ?4, ?5, 1)
               ON CONFLICT(unique_id) DO UPDATE SET
                   state = ?2,
                   broadcast_needed = 1,
                   pubkey_mlkem768 = ?4,
                   pubkey_x25519 = ?5)",
            self_id,
            static_cast<int>(device::State::Registered),
            epoch_seconds(clock_now_s()),
            std::as_bytes(std::span{key.mlkem768_pub}),
            std::as_bytes(std::span{key.x25519_pub}));

    // In view from the moment it exists, rather than from when its first message comes back from
    // the swarm: until then another group alongside it would read as our having been cut off.
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

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    auto now = epoch_seconds(clock_now_s());
    c.prepared_exec("INSERT INTO device_privkeys (created, seed) VALUES (?, ?)", now, seed);

    // Update our own device row with the new pubkeys and bump seqno so the change gets broadcast.
    // If no row exists yet, this is a no-op; the new pubkeys will be read from the active device
    // keys when the row is first created.
    c.prepared_exec(
            "UPDATE devices"
            " SET pubkey_mlkem768 = ?, pubkey_x25519 = ?, seqno = seqno + 1, timestamp = ?"
            " WHERE unique_id = ?",
            keys.mlkem768_pub,
            keys.x25519_pub,
            now,
            self_id);

    tx.commit();

    log::info(cat, "New rotating device keys generated: {}", keys);

    return keys;
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

    c.prepared_exec(
            "DELETE FROM device_account_keys WHERE rotated < ?",
            epoch_seconds(clock_now_s() - ACCOUNT_KEY_RETENTION));

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

namespace {

    // Builds a device::Info from the fields of a devices table row (excluding the row id, changes,
    // and kicked_timestamp columns, which are not part of device::Info).
    device::Info fill_device_info(
            std::span<const std::byte, 32> devid,
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
    // set to the 32-byte device id.
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
                 sqlite::blob_guts<std::array<std::byte, 32>>,
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

std::pair<device::Info, bool> Devices::_device_info() {
    assert(on_loop());
    auto devs = devices(true, true, true, self_id);
    if (auto it = devs.find(self_id); it != devs.end()) {
        // Read the state out before the move: the elements of a braced-init-list are evaluated in
        // order, so testing `it->second` in the second element is testing a moved-from Info.
        bool registered = it->second.state == device::State::Registered;
        return {std::move(it->second), registered};
    }
    return {device::Info{.id = self_id}, false};
}

bool device::Info::same_user_fields(const Info& other) const {
    auto fields = [](const Info& i) {
        return std::tie(i.type, i.other_device, i.description, i.version, i.extra);
    };
    return fields(*this) == fields(other);
}

void Devices::update_info(device::Info info, result_function<> cb) {
    async([this, info = std::move(info)] { _update_info(info); }, std::move(cb));
}

void Devices::update_info(const device::Info& info, await_t) {
    jq().call_get([this, &info] { _update_info(info); });
}

void Devices::_update_info(const device::Info& info) {
    assert(on_loop());
    auto [current, is_registered] = _device_info();

    // Early-exit if nothing changed: no seqno bump, no push triggered.
    // current.seqno == 0 means no row exists yet (default-init sentinel; real rows have seqno >=
    // 1).
    if (current.seqno > 0 && current.same_user_fields(info))
        return;

    auto keys = active_device_keys();
    auto& front_key = keys.front();
    auto now = clock_now_s();
    auto ver = info.version[0] * 1000000 + info.version[1] * 1000 + info.version[2];

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    auto dev_id = c.prepared_get<int64_t>(
            R"(INSERT INTO devices
                (unique_id, state, seqno, timestamp, device_type, description, version,
                 pubkey_mlkem768, pubkey_x25519)
               VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(unique_id) DO UPDATE SET
                   seqno = seqno + 1,
                   timestamp = excluded.timestamp,
                   device_type = excluded.device_type,
                   description = excluded.description,
                   version = excluded.version
               RETURNING id)",
            self_id,
            static_cast<int>(device::State::Unregistered),
            now.time_since_epoch().count(),
            info.encoded_type(),
            info.description,
            ver,
            std::as_bytes(std::span{front_key.mlkem768_pub}),
            std::as_bytes(std::span{front_key.x25519_pub}));

    c.prepared_exec("DELETE FROM device_unknown WHERE device = ?", dev_id);
    for (const auto& [key, val] : info.extra) {
        auto encoded = std::visit([](const auto& v) { return oxenc::bt_serialize(v); }, val);
        c.prepared_exec(
                "INSERT INTO device_unknown (device, key, bt_value) VALUES (?, ?, ?)",
                dev_id,
                key,
                to_span<std::byte>(encoded));
    }

    tx.commit();

    _devices_changed = true;
    _flush_events();
}

namespace {

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

    // Encodes the fields of a device::Info into an already-opened bt_dict_producer (passed as
    // rvalue to allow callers to pass sub-producers directly from append_dict()).
    void encode_device_info(oxenc::bt_dict_producer&& devout, const device::Info& info) {
        auto xit = info.extra.cbegin();
        auto xend = info.extra.cend();
        write_next(devout, "#", info.seqno, xit, xend);
        write_next(devout, "@", info.timestamp.time_since_epoch().count(), xit, xend);
        write_next(devout, "M", info.pk_mlkem768, xit, xend);
        write_next(devout, "X", info.pk_x25519, xit, xend);
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

    std::string encode_group_payload(
            const device::map& devices, std::span<const AccountKeySeed> acc_keys) {
        oxenc::bt_dict_producer out;

        {
            auto devs = out.append_dict("D");
            for (const auto& [id, info] : devices) {

                std::string_view id_sv{reinterpret_cast<const char*>(id.data()), id.size()};

                if (info.state == device::State::Pending) {
                    log::debug(
                            cat,
                            "Skipping pending device {} in device group data",
                            oxenc::to_hex(id));
                    continue;
                } else if (
                        info.state == device::State::Kicked || info.state == device::State::Left) {
                    // A removed device goes in as a bare timestamp: that is how every other device
                    // learns it is gone, since a record merely absent from a message means
                    // "unchanged" rather than "removed".  Negated for one that left, which is what
                    // keeps it out of the `kicked` list.
                    //
                    // TODO: we should stop writing devices gone a long time ago.  Pruning means
                    // dropping them from *this payload* and never from the table -- the budget is
                    // on what the message carries, a local row costs nothing, and forgetting one
                    // would lower its rank and let a stale group resurrect the device.
                    assert(info.kicked);
                    auto t = info.kicked->time_since_epoch().count();
                    devs.append(id_sv, info.state == device::State::Left ? -t : t);
                    continue;
                } else if (info.state == device::State::Unregistered) {
                    // Never in the group rather than removed from it, so there is nothing to say
                    // about it: our own row before the group exists, and nothing else.
                    log::debug(cat, "Skipping unregistered device {}", oxenc::to_hex(id));
                    continue;
                }

                encode_device_info(devs.append_dict(id_sv), info);
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
            std::span<const std::byte, 32> device_id,
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

        read_extras(dev, "d", info.extra);
        info.description = dev.maybe<std::string_view>("d").value_or(""sv);

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

    // The device record a stored link request asks to have admitted.  Already verified when the
    // request was received.
    device::Info requested_record(
            std::span<const std::byte, 32> id, std::span<const std::byte> encoded) {
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

    // Decodes the plaintext bt-encoded device group payload.  The returned device map will include
    // both full device records and tombstoned devices: the latter have a mostly default-constructed
    // Info where only id, state (Kicked or Left), and kicked are set.
    GroupPayload decode_group_payload(std::span<const std::byte> data) {
        GroupPayload result;

        oxenc::bt_dict_consumer in{data};
        auto devs = in.require<bt_dict_consumer>("D");

        while (!devs.is_finished()) {
            auto in_id = devs.key();
            if (in_id.size() != 32)
                throw std::runtime_error{
                        "Invalid encoded device data: unexpected {}-byte key in device dict (expected 32)"_format(
                                in_id.size())};

            std::array<std::byte, 32> id;
            std::memcpy(id.data(), in_id.data(), 32);
            auto [it, ins] = result.devices.try_emplace(id);
            if (!ins)
                throw std::runtime_error{"Invalid encoded device data: duplicate device ids"};

            auto& info = it->second;
            info.id = id;

            if (devs.is_integer()) {
                // A tombstone: the time the device was removed, or negated, the time it left.
                // Either way the id is spent, and the device must generate a new one to come back.
                auto t = devs.consume_integer<int64_t>();
                if (t == 0 || t == std::numeric_limits<int64_t>::min())
                    throw std::runtime_error{"Invalid encoded device data: invalid tombstone"};
                info.state = t > 0 ? device::State::Kicked : device::State::Left;
                info.kicked.emplace(std::chrono::seconds{t > 0 ? t : -t});
            } else {
                // The encoded record itself, rather than what we would make of it again: taking the
                // view costs nothing here, and re-encoding to hash would.
                auto raw = devs.consume_dict_data();
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

    // Encrypts or decrypts a group identifier for a message's outer `@` (XChaCha20 being its own
    // inverse): readable by any holder of the account seed, and different in every message to
    // anyone else, the nonce coming from that message's A.
    std::array<std::byte, 8> crypt_group_id(
            std::span<const std::byte, 8> in,
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> seed) {
        cleared_b32 key;
        hash::blake2b_pers(key, PERS_GROUP_ID_KEY, seed);
        std::array<std::byte, encryption::XCHACHA20_NONCEBYTES> nonce;
        hash::blake2b_pers(nonce, PERS_GROUP_ID_NONCE, A);
        std::array<std::byte, 8> out;
        encryption::xchacha20_xor(out, in, nonce, key);
        return out;
    }

    // A removed device's entry in a message's `kicked` list: computable only with the account seed,
    // and different in every message, being keyed by that message's ephemeral A.
    std::array<std::byte, 16> kicked_entry(
            std::span<const std::byte, 32> A,
            std::span<const std::byte, 32> seed,
            std::span<const std::byte, 32> device_id) {
        std::array<std::byte, 16> out;
        hash::blake2b_key_pers(out, A, PERS_KICKED, seed, device_id);
        return out;
    }

    // Device group payloads are null-padded to a multiple of this before encryption so that the
    // encrypted size reveals only which bucket the payload falls in, not what it contains.  A
    // bucket is four devices at a budget of 1600 bytes each, a deliberate overestimate of a
    // ~1341-byte record, with the remainder of a bucket left for removal tombstones.
    constexpr size_t DEVICE_PAYLOAD_PADDING = 4 * 1600;

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

}  // namespace

std::chrono::sys_time<std::chrono::minutes> device::GroupId::created() const {
    return std::chrono::sys_time<std::chrono::minutes>{
            std::chrono::minutes{oxenc::load_little_to_host<uint32_t>(value.data())}};
}

std::array<std::string_view, 21> device::GroupId::sas() const {
    std::array<std::byte, 16> seed;
    hash::blake2b_pers(seed, PERS_GROUP_SAS, value);
    return sas_from_seed(seed);
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

std::optional<device::GroupId> Devices::_group_of(std::span<const std::byte> message) {
    oxenc::bt_dict_consumer in{message};
    in.require<std::string_view>("");
    if (!in.skip_until("@"))
        return std::nullopt;
    auto encrypted = in.consume_span<std::byte, 8>();
    auto A = in.require_span<std::byte, 32>("A");
    auto seed = core.globals.account_seed();
    return device::GroupId{crypt_group_id(encrypted, A, seed.seed())};
}

std::vector<std::byte> Devices::encrypt_device_data(const device::map& devices) {
    cleared_b32 a;
    random::fill(a);

    auto A = x25519::scalarmult_base(a);

    // Who can read this, which is not the same as who appears in it.  A kicked device is written
    // into the payload -- a tombstone carrying when it was kicked is how every other device learns
    // it is gone -- but must not be given a key, which is the entire point of removing it.  A
    // pending device is in neither: it is not in the group until someone accepts it.
    std::vector<const device::Info*> recipients;
    for (const auto& [id, info] : devices)
        if (info.state == device::State::Registered)
            recipients.push_back(&info);

    // Removals among the tombstones, announced to the devices removed, which have no key to read
    // them from the payload.  Departures are left out: the device that left knows, and would read
    // its own entry as a removal.  Padded to a multiple of 4 and shuffled, like the recipient
    // lists, so that the length says only which bucket the removal count is in.
    // A group established before groups had identifiers gets one from whichever of its devices
    // pushes first, and the rest adopt it from that message.
    auto group_id = _group_id();
    if (!group_id) {
        group_id = new_group_id();
        _set_group_id(*group_id);
        log::info(cat, "Gave this device group an identifier");
    }
    std::array<std::byte, 8> group_id_enc;

    std::vector<std::byte> kicked_raw;
    {
        auto seed = core.globals.account_seed();
        group_id_enc = crypt_group_id(group_id->value, A, seed.seed());

        std::vector<const std::array<std::byte, 32>*> removed;
        for (const auto& [id, info] : devices)
            if (info.state == device::State::Kicked)
                removed.push_back(&id);

        std::vector<size_t> slots((removed.size() + 3) / 4 * 4);
        std::iota(slots.begin(), slots.end(), 0);
        std::ranges::shuffle(slots, csrng);

        kicked_raw.resize(16 * slots.size());
        random::fill(kicked_raw);
        for (size_t i = 0; i < removed.size(); i++)
            std::ranges::copy(
                    kicked_entry(A, seed.seed(), *removed[i]), kicked_raw.begin() + 16 * slots[i]);
    }

    int padded_count = recipients.size();
    padded_count = (padded_count + 3) / 4 * 4;

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

    auto plaintext_devices = encode_group_payload(devices, acc_keys);
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
// tombstones of one kind the later wins.  Every group message carries every tombstone, so most of
// these restate what is already held, and only a real change returns a row.
static const std::string TOMBSTONE_SQL =
        "INSERT INTO devices"
        " (unique_id, state, seqno, timestamp, device_type, description, version,"
        "  pubkey_mlkem768, pubkey_x25519, kicked_timestamp)"
        " VALUES (?2, ?3, 0, ?1, '', '', 0, zeroblob(1184), zeroblob(32), ?1)"
        " ON CONFLICT(unique_id) DO UPDATE SET"
        "     state = excluded.state, kicked_timestamp = excluded.kicked_timestamp,"
        "     broadcast_needed = CASE WHEN state = {} THEN 1 ELSE broadcast_needed END"
        "   WHERE (excluded.state, excluded.kicked_timestamp) > (state, kicked_timestamp)"
        " RETURNING id"_format(static_cast<int>(device::State::Registered));

static const std::string REGISTER_DEVICE_SQL =
        "UPDATE devices SET broadcast_needed = 1 WHERE id = ?";

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
        std::span<const std::byte, 32> id,
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
// time, or having since pruned the tombstone -- has no reason to refuse it, and would go on
// treating the device as a member and encrypting to it.  Nothing reconciles that afterwards, since
// a record absent from a message means "unchanged" rather than "removed", so the two devices would
// hold permanently different groups.  A tombstone propagates where a refusal does not.
//
// The timestamp is moved to now rather than left at the original removal, because retention keeps
// the most recently removed: a tombstone left to age could be evicted while the device it names is
// still trying to return, either by waiting out the window or by provoking enough other removals to
// displace it.
//
// Applies equally to a device that left: it holds the seed just the same.
static const std::string REASSERT_TOMBSTONE_SQL =
        "UPDATE devices SET kicked_timestamp = ?, broadcast_needed = 1 WHERE unique_id = ?";

void Devices::receive_device_group_message(
        std::span<const std::byte> data, const std::string& hash, sys_ms timestamp) {
    GroupPayload payload;
    try {
        auto raw = decrypt_device_data(std::as_bytes(data));
        payload = decode_group_payload(raw);
    } catch (const device::decryption_failed& e) {
        if (_names_us_kicked(data)) {
            // When we learned of it, which is the nearest we can say: the removal time is in the
            // payload we can no longer read.  Only from a live state, so that every later message
            // still naming us leaves it where it is.
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
        // cannot read means another device holds our place.  Older ones say nothing: they are from
        // before we joined, or snapshots overtaken since -- see DISPLACEMENT_GRACE.
        auto group = _group_of(data);
        auto read_at = core.globals.get_integer(read_at_key);
        if (group && group == _group_id() && read_at &&
            timestamp.time_since_epoch() >
                    std::chrono::milliseconds{*read_at} + DISPLACEMENT_GRACE &&
            _member()) {
            core.globals.set(displaced_key, int64_t{timestamp.time_since_epoch().count()});
            log::warning(cat, "Another device has taken this device's place in its device group");
            return;
        }
        log::warning(cat, "Ignoring incoming device group message: {}", e.what());
        return;
    }

    auto theirs = _group_of(data);
    auto ours = _group_id();

    // A member of the group, or of one that predates identifiers -- which adopts this one's, or
    // hears from a device yet to give it one -- merges whatever it can read of it.
    bool member = conn().prepared_maybe_get<int>(
                          "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                          self_id,
                          static_cast<int>(device::State::Registered)) &&
                  (!ours || !theirs || *theirs == *ours);

    // Anything else is ours only as an admission on one of our own requests: from outside any
    // group, or from inside one, switching.  Being able to read it shows only that some holder of
    // the seed encrypted it to us, so it admits us only on a request whose SAS the user confirmed
    // -- the one the accepting device showed, identified by the record it admitted.
    std::optional<OwnRequest> accepted;
    if (!member) {
        auto self = payload.devices.find(self_id);
        if (theirs && self != payload.devices.end() &&
            self->second.state == device::State::Registered)
            accepted = _own_request_admitted(*theirs, self->second);
        if (!accepted) {
            log::warning(cat, "Not merging a readable device group message from another group");
            return;
        }
        if (!accepted->confirmed) {
            // Held only for the request the user is looking at.  One they moved on from by asking
            // again is not what they will confirm; the newer request admits them instead.
            if (auto newest = _newest_request(); !newest || newest->row != accepted->row) {
                log::info(cat, "Admitted on an earlier request the user never confirmed; ignoring");
                return;
            }
            conn().prepared_exec(
                    "UPDATE device_own_requests SET admission = ?, admission_hash = ?,"
                    " admission_at = ? WHERE id = ?",
                    data,
                    hash,
                    timestamp.time_since_epoch().count(),
                    accepted->row);
            log::info(
                    cat, "Admitted to a device group; holding it until the user confirms the SAS");
            return;
        }
    }
    bool admitting = accepted.has_value();
    bool switching = admitting && ours && *ours != *theirs;

    if (switching) {
        _leave_group();
        ours.reset();
    }

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    // Admitted, or in a group that predates identifiers: either way this is the group's.
    if (theirs && !ours)
        _set_group_id(*theirs);

    // Merge incoming account keys.  New seeds are inserted and the rotation trigger applies
    // tie-breaking: latest created wins (smallest seed as tiebreaker), so concurrent rotations
    // from multiple devices converge deterministically.  For seeds we already have, we reconcile
    // the `rotated` column: if both sides have rotated at different times, take the minimum; if
    // only one side has rotated, adopt that rotation.
    for (const auto& k : payload.account_keys) {
        auto keys = keys_from_seed<AccountKeys>(k.seed);
        c.prepared_exec(
                "INSERT INTO device_account_keys"
                " (created, rotated, seed, pubkey_mlkem768, pubkey_x25519)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT (seed) DO UPDATE SET"
                "   rotated = COALESCE(MIN(excluded.rotated, rotated), excluded.rotated, rotated)",
                k.created,
                k.rotated,
                k.seed,
                keys.mlkem768_pub,
                keys.x25519_pub);
    }

    bool departed = false;
    std::vector<std::array<std::byte, 32>> members;
    for (const auto& [id, info] : payload.devices) {
        if (info.state == device::State::Kicked || info.state == device::State::Left) {
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
                if (info.state == device::State::Left &&
                    was < static_cast<int>(device::State::Left))
                    departed = true;
                // Gone from the group, rather than a tombstone for a device we never knew of.
                if (was == static_cast<int>(device::State::Registered) && id != self_id)
                    members.push_back(id);
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
            c.prepared_exec(REGISTER_DEVICE_SQL, *dev_id);
            c.prepared_exec(ANSWER_REQUEST_SQL, *dev_id);
            if (id != self_id)
                members.push_back(id);
        } else {
            answer_replacements(c, *dev_id, id, info);
        }
    }

    // A device that left still holds every account key we have, and could not rotate to one it
    // lacks on our behalf: the rotation falls to whichever remaining member learns of it first --
    // or to several, whose rotations then settle on one key as any crossing rotations do.  Not for
    // a removal, which the removing device rotated for in the same step.
    if (departed && _member()) {
        log::info(cat, "A device left the group; rotating the account key");
        rotate_account_keys();
    }

    if (theirs && theirs == _group_id())
        _note_read(timestamp);

    // Recorded whether or not the merge changed anything: a message that told us only what we
    // already knew is just as redundant as one that told us something new, and our next push
    // carries its contents either way.  A message we could not decrypt never reaches here.
    if (!hash.empty())
        c.prepared_exec(
                "INSERT INTO device_group_merged (hash) VALUES (?) ON CONFLICT DO NOTHING", hash);

    tx.commit();

    // Being admitted, every member is new to us, and none of them is news.
    if (admitting)
        _forget_own_requests();
    else
        _member_changes.insert(_member_changes.end(), members.begin(), members.end());
}

void Devices::_leave_group() {
    assert(on_loop());
    auto c = conn();
    auto old = _group_id();

    std::vector<std::string> messages;
    for (auto hash : c.prepared_results<std::string>("SELECT hash FROM device_group_merged"))
        messages.push_back(std::move(hash));

    // A departure for the members left, so they stop encrypting to us and rotate to a key we do not
    // hold, pushed as an ordinary group message: so it replaces the old group's messages as any
    // push does.  With nobody left, the messages are only deleted: nothing could read them, and
    // devices elsewhere would go on alerting about a group nobody is in.
    std::vector<SwarmStore> stores;
    if (c.prepared_get<int>(
                "SELECT count(*) FROM devices WHERE state = ? AND unique_id != ?",
                static_cast<int>(device::State::Registered),
                self_id) > 0) {
        c.prepared_exec(
                "UPDATE devices SET state = ?, kicked_timestamp = ? WHERE unique_id = ?",
                static_cast<int>(device::State::Left),
                epoch_seconds(clock_now_s()),
                self_id);
        stores.push_back(
                {.ns = config::Namespace::Devices,
                 .data = encrypt_device_data(devices(true, true, true)),
                 .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(DEVICE_GROUP_TTL)});
    }
    if (core.network())
        core._swarm_push(std::move(stores), std::move(messages), [](auto results) {
            if (!results)
                log::warning(cat, "Could not leave the old device group cleanly");
        });
    else
        log::warning(cat, "Leaving the old device group without telling it: no network");

    // The group we have just left is not one to be alerted about.
    if (old)
        c.prepared_exec(
                "UPDATE device_groups SET dismissed = 1 WHERE group_id = ?",
                std::span<const std::byte>{old->value});
    _forget_group();
    log::info(cat, "Left the device group, to join another");
}

void Devices::_record_group(const SwarmMessage& msg) {
    oxenc::bt_dict_consumer in{msg.data};
    in.require<std::string_view>("");
    if (!in.skip_until("@"))
        return;
    auto encrypted_id = in.consume_span<std::byte, 8>();
    auto A = in.require_span<std::byte, 32>("A");
    auto X = in.require_span<std::byte, 32>("X");

    // Checked even though only a seed holder could have encrypted the identifier: without the
    // signature a storage server could still replay one group's identifier with a link key of its
    // own, and have requests to join that group encrypted to it.
    in.require_signature(
            "~", [this](std::span<const std::byte> body, std::span<const std::byte> sig) {
                if (sig.size() != 64 ||
                    !ed25519::verify(sig.first<64>(), core.globals.pubkey_ed25519(), body))
                    throw std::runtime_error{"Invalid device group message signature"};
            });

    auto seed = core.globals.account_seed();
    auto group = crypt_group_id(encrypted_id, A, seed.seed());
    conn().prepared_exec(
            "INSERT INTO device_groups (group_id, link_x25519, seen_at, expires_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(group_id) DO UPDATE SET"
            "   link_x25519 = CASE WHEN excluded.seen_at >= seen_at"
            "       THEN excluded.link_x25519 ELSE link_x25519 END,"
            "   seen_at = MAX(seen_at, excluded.seen_at),"
            "   expires_at = MAX(expires_at, excluded.expires_at)",
            std::span<const std::byte>{group},
            X,
            epoch_seconds(std::chrono::floor<std::chrono::seconds>(msg.timestamp)),
            epoch_seconds(std::chrono::floor<std::chrono::seconds>(msg.expiry)));
}

bool Devices::_names_us_kicked(std::span<const std::byte> data) {
    oxenc::bt_dict_consumer in{data};
    in.require<std::string_view>("");
    auto A = in.require_span<std::byte, 32>("A");
    if (!in.skip_until("k"))
        return false;
    auto kicked = in.consume_span<std::byte>();
    if (kicked.size() % 16 != 0)
        return false;

    auto seed = core.globals.account_seed();
    auto ours = kicked_entry(A, seed.seed(), self_id);
    for (size_t i = 0; i < kicked.size(); i += 16)
        if (std::ranges::equal(kicked.subspan(i, 16), ours))
            return true;
    return false;
}

void Devices::request_link(device::GroupId group, result_function<OutgoingLinkRequest> cb) {
    enqueue([this, group, cb = std::move(cb)]() mutable {
        // Everything that can throw comes before the upload takes `cb`, so this reports at most
        // once.
        try {
            _request_link(group, cb);
        } catch (const std::exception& e) {
            detail::log_component_failure(e);
            if (cb)
                cb(unexpected{error_from(e)});
        }
    });
}

void Devices::_request_link(
        const device::GroupId& group, result_function<OutgoingLinkRequest>& cb) {
    assert(on_loop());

    // Also what stops a device with no account getting as far as building a request, since a
    // network cannot be attached without one.
    if (!core.network())
        throw session::error{err::network_unavailable, "Cannot request a link: no network"};
    // Not even to switch groups: leaving its old one would announce a departure under an id that is
    // now another device's.
    if (_displaced())
        throw session::error{
                err::removed,
                "Another device holds this device's place; it must ask under a new device id"};
    if (_group_id() == group && _device_info().second)
        throw session::error{err::already_registered, "This device is already in that group"};

    auto link_x25519 = conn().prepared_maybe_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
            "SELECT link_x25519 FROM device_groups WHERE group_id = ? AND expires_at > ?",
            std::span<const std::byte>{group.value},
            epoch_seconds(clock_now_s()));
    if (!link_x25519)
        throw session::error{
                err::unknown_group, "Cannot request a link: no such group is in the swarm"};

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
            int,
            int>(
            "SELECT id, group_id, sas_seed, timestamp, expires_at, confirmed,"
            "       admission_at IS NOT NULL"
            "  FROM device_own_requests {} ORDER BY id DESC LIMIT 1"_format(where),
            bind...);
    if (!found)
        return std::nullopt;
    auto& [row, group, seed, asked, expires, confirmed, held] = *found;
    return OwnRequest{
            .row = row,
            .group = device::GroupId{group},
            .sas_seed = seed,
            .asked = from_epoch_s(asked),
            .expires = expires ? std::optional{from_epoch_s(*expires)} : std::nullopt,
            .confirmed = confirmed != 0,
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
            .expires = newest->expires.value_or(newest->asked + LINK_REQUEST_TTL),
            .confirmed = newest->confirmed,
            .accepted = newest->held};
}

void Devices::confirm_link(result_function<bool> cb) {
    async([this] { return _confirm_link(); }, std::move(cb));
}

bool Devices::confirm_link(await_t) {
    return jq().call_get([this] { return _confirm_link(); });
}

bool Devices::_asking() {
    if (conn().prepared_maybe_get<int>(
                "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                self_id,
                static_cast<int>(device::State::Pending)))
        return true;
    auto newest = _newest_request();
    if (!newest)
        return false;
    if (newest->held)
        return true;
    // From inside a group, asking to switch: only while the request is live, since our own row
    // says nothing of it.
    return newest->expires && *newest->expires > clock_now() && newest->group != _group_id();
}

bool Devices::_confirm_link() {
    assert(on_loop());
    if (!_asking())
        return false;
    auto newest = _newest_request();
    if (!newest)
        return false;

    auto c = conn();
    c.prepared_exec("UPDATE device_own_requests SET confirmed = 1 WHERE id = ?", newest->row);
    if (!newest->held)
        return true;

    std::vector<std::byte> admission;
    std::string hash;
    int64_t at = 0;
    for (auto [data, h, t] : c.prepared_results<sqlite::blob, std::string, int64_t>(
                 "SELECT admission, IFNULL(admission_hash, ''), admission_at"
                 "  FROM device_own_requests WHERE id = ?",
                 newest->row)) {
        admission.assign(data.begin(), data.end());
        hash = std::move(h);
        at = t;
    }
    receive_device_group_message(admission, hash, sys_ms{std::chrono::milliseconds{at}});
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

    // After every request before it, even within the same second: the timestamp is what tells an
    // admission which of our requests it accepted.
    info.id = self_id;
    info.seqno++;
    info.timestamp = std::max(
            clock_now_s(),
            from_epoch_s(c.prepared_get<int64_t>(
                    "SELECT IFNULL(MAX(timestamp) + 1, 0) FROM device_own_requests")));

    // Always use the current active device keys for the pubkeys in the link request, regardless
    // of what is stored in the DB, as the DB may lag a key rotation.
    auto keys = active_device_keys();
    std::memcpy(
            info.pk_x25519.data(),
            reinterpret_cast<const std::byte*>(keys.front().x25519_pub.data()),
            info.pk_x25519.size());
    std::memcpy(
            info.pk_mlkem768.data(),
            reinterpret_cast<const std::byte*>(keys.front().mlkem768_pub.data()),
            info.pk_mlkem768.size());

    // Outside a group, our own row moves to Pending with the updated seqno, timestamp, and pubkeys:
    // Pending is what says we are waiting.  In one, we are asking to switch to another, and stay a
    // working member of ours, row untouched, until we are admitted.
    auto ver = info.version[0] * 1000000 + info.version[1] * 1000 + info.version[2];
    if (!is_registered)
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
            " SET admission = NULL, admission_hash = NULL, admission_at = NULL");
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

    in.require_signature(
            "~", [this](std::span<const std::byte> body, std::span<const std::byte> sig) {
                if (sig.size() != 64 ||
                    !ed25519::verify(sig.first<64>(), core.globals.pubkey_ed25519(), body))
                    throw std::runtime_error{
                            "Invalid encrypted device message: signature verification failed"};
            });

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
    for (auto account_seed : conn().prepared_results<sqlite::blobn<32>>(
                 "SELECT seed FROM device_account_keys WHERE substr(pubkey_x25519, 1, 2) = ?",
                 std::span<const std::byte>{prefix})) {
        auto keys = keys_from_seed<AccountKeys>(account_seed);
        cleared_b32 shared_x;
        if (!x25519::scalarmult(shared_x, keys.x25519_sec, E))
            continue;
        auto [key, nonce] = link_request_key(shared_x, E, keys.x25519_pub);
        std::vector<std::byte> plaintext(encrypted.size() - encryption::XCHACHA20_ABYTES);
        if (encryption::xchacha20poly1305_decrypt(plaintext, encrypted, nonce, key))
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
        auto in_id = pt.require_span<unsigned char, 32>("I");
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
        pt.require_signature(
                "~", [this](std::span<const std::byte> body, std::span<const std::byte> sig) {
                    if (sig.size() != 64 ||
                        !ed25519::verify(sig.first<64>(), core.globals.pubkey_ed25519(), body))
                        throw std::runtime_error{"signature verification failed"};
                });
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
    // the insert so that exactly one request per device is ever pending.
    c.prepared_exec(
            "UPDATE device_link_requests SET status = {} WHERE device = ? AND status = {}"_format(
                    static_cast<int>(device::LinkStatus::Superseded),
                    static_cast<int>(device::LinkStatus::Pending)),
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
                 sqlite::blob_guts<std::array<std::byte, 32>>>(
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

    auto request = c.prepared_maybe_get<int64_t, int>(
            "SELECT device, replaces FROM device_link_requests"
            " WHERE id = ? AND status = {} AND expires_at > ?"_format(
                    static_cast<int>(device::LinkStatus::Pending)),
            *row,
            epoch_seconds(clock_now_s()));
    if (!request)
        return false;
    auto [dev, replaces] = *request;

    // A new device only from Pending: one kicked since the request arrived is gone for good, and
    // the rank rule would refuse to lower it anyway.
    bool admitted = replaces ? _replace_record(*row)
                             : c.prepared_maybe_get<int64_t>(
                                        "UPDATE devices SET state = ?, broadcast_needed = 1"
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
    return true;
}

bool Devices::_replace_record(int64_t row) {
    assert(on_loop());
    auto c = conn();
    std::optional<device::Info> info;
    for (auto [record, id, seqno] :
         c.prepared_results<sqlite::blob, sqlite::blob_guts<std::array<std::byte, 32>>, int64_t>(
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
    c.prepared_exec(REGISTER_DEVICE_SQL, *dev);

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

    if (delete_from_swarm) {
        if (core.network())
            core._swarm_push({}, {std::move(*ignored)}, [](auto results) {
                if (!results)
                    log::warning(cat, "Could not delete an ignored link request from the swarm");
            });
        else
            log::warning(cat, "Not deleting an ignored link request from the swarm: no network");
    }
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
    auto ours = _group_id();
    auto c = conn();

    bool ours_present = false;
    for (auto [group, seen, dismissed] :
         c.prepared_results<sqlite::blob_guts<std::array<std::byte, 8>>, int64_t, int>(
                 "SELECT group_id, seen_at, dismissed FROM device_groups"
                 " WHERE expires_at > ? ORDER BY seen_at DESC",
                 epoch_seconds(clock_now_s()))) {
        device::GroupId id{group};
        if (ours && id == *ours)
            ours_present = true;
        else
            out.others.push_back({id, from_epoch_s(seen), dismissed != 0});
    }

    auto own = static_cast<device::State>(
            c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", self_id)
                    .value_or(static_cast<int>(device::State::Unregistered)));
    if (own == device::State::Registered)
        out.group = ours;

    if (!_fetched)
        return out;

    switch (own) {
        case device::State::Kicked: out.membership = device::Membership::Removed; break;
        case device::State::Registered:
            // None of ours left is only alarming beside another's: alone, it is a group whose
            // messages have yet to reach the swarm, or expired while every device was away, and
            // our next push restores them.
            out.membership = _displaced()                         ? device::Membership::Displaced
                           : !ours_present && !out.others.empty() ? device::Membership::CutOff
                                                                  : device::Membership::InGroup;
            break;
        case device::State::Pending: out.membership = device::Membership::Waiting; break;
        default: {
            // Admitted after the request lapsed here, and waiting for the user to confirm it.
            auto newest = _newest_request();
            out.membership = newest && newest->held ? device::Membership::Waiting
                           : out.others.empty()     ? device::Membership::NoGroup
                                                    : device::Membership::GroupsVisible;
        }
    }
    return out;
}

void Devices::_rebaseline_membership() {
    if (auto m = _membership().membership; m != device::Membership::Unknown)
        _reported_membership = m;
}

void Devices::renew_device_identity(result_function<bool> cb) {
    async([this] { return _renew_device_identity(); }, std::move(cb));
}

bool Devices::renew_device_identity(await_t) {
    return jq().call_get([this] { return _renew_device_identity(); });
}

void Devices::_forget_group() {
    assert(on_loop());
    auto c = conn();
    // Its devices, ourselves included: a group started from these would carry them over as members,
    // and a group joined says who is in it.  Its account keys, which never carry into another group
    // -- a group joined brings its own, and a group started mints a fresh one.
    c.prepared_exec("DELETE FROM devices");
    c.prepared_exec("DELETE FROM device_group_merged");
    c.prepared_exec("DELETE FROM device_account_keys");
    core.globals.erase(group_id_key);
    core.globals.erase(read_at_key);
    core.globals.erase(displaced_key);
}

bool Devices::_displaced() {
    return core.globals.get_integer(displaced_key).has_value();
}

bool Devices::_member() {
    return !_displaced() && conn().prepared_maybe_get<int>(
                                    "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                                    self_id,
                                    static_cast<int>(device::State::Registered));
}

void Devices::_note_read(sys_ms timestamp) {
    int64_t ms = timestamp.time_since_epoch().count();
    if (auto read_at = core.globals.get_integer(read_at_key); !read_at || ms > *read_at)
        core.globals.set(read_at_key, ms);

    // Read again at or past what displaced us, which only a member could: the group took us back,
    // or what looked like displacement was a snapshot that had yet to hear of us after all.
    if (auto displaced = core.globals.get_integer(displaced_key); displaced && ms >= *displaced) {
        core.globals.erase(displaced_key);
        log::info(cat, "This device can read its device group again");
    }
}

bool Devices::_renew_device_identity() {
    assert(on_loop());
    if (!_displaced() && !conn().prepared_maybe_get<int>(
                                 "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                                 self_id,
                                 static_cast<int>(device::State::Kicked)))
        return false;

    // Before the transaction, which it would otherwise nest inside.
    rotate_device_keys();

    std::array<std::byte, 32> id;
    random::fill(id);
    {
        auto c = conn();
        SQLite::Transaction tx{c.sql};
        _forget_group();
        core.globals.set(dev_key, std::span<const std::byte>{id});
        _forget_own_requests();
        tx.commit();
    }

    log::info(cat, "Replaced removed device id {} with {}", self_id, id);
    self_id = id;
    _reqid_by_row.clear();
    _row_by_reqid.clear();
    _ended.clear();

    _rebaseline_membership();
    _flush_events();
    return true;
}

void Devices::start_group(result_function<device::GroupId> cb) {
    async([this] { return _start_group(); }, std::move(cb));
}

device::GroupId Devices::start_group(await_t) {
    return jq().call_get([this] { return _start_group(); });
}

device::GroupId Devices::_start_group() {
    assert(on_loop());
    switch (_membership().membership) {
        case device::Membership::Unknown:
            throw session::error{
                    err::membership_unknown,
                    "Cannot start a group before a fetch has shown what the swarm holds"};
        case device::Membership::InGroup:
        case device::Membership::CutOff:
            throw session::error{err::already_registered, "This device is already in a group"};
        case device::Membership::Removed:
        case device::Membership::Displaced:
            // Its tables still hold the group it is no longer in, which a group started from them
            // would carry on as its own members.
            throw session::error{
                    err::removed,
                    "This device is no longer in its group; it must rejoin under a new device id "
                    "before starting one"};
        case device::Membership::Waiting: _withdraw_own_request(); break;
        case device::Membership::NoGroup:
        case device::Membership::GroupsVisible: break;
    }

    // Whatever it held before is no group's, the group starts with a fresh key, and an admission on
    // anything it asked before would take it straight back out.
    _forget_group();
    _forget_own_requests();
    _mark_group_owed();
    establish_group();
    auto group = _group_id();
    if (!group)
        throw std::logic_error{"Started a group but it has no identifier"};
    log::info(cat, "Started a new device group");

    _devices_changed = true;
    _rebaseline_membership();
    _flush_events();
    return *group;
}

void Devices::dismiss_group(device::GroupId group, result_function<bool> cb) {
    async([this, group] { return _dismiss_group(group); }, std::move(cb));
}

bool Devices::dismiss_group(const device::GroupId& group, await_t) {
    return jq().call_get([this, &group] { return _dismiss_group(group); });
}

bool Devices::_dismiss_group(const device::GroupId& group) {
    assert(on_loop());
    return conn()
            .prepared_maybe_get<int>(
                    "UPDATE device_groups SET dismissed = 1 WHERE group_id = ? RETURNING 1",
                    std::span<const std::byte>{group.value})
            .has_value();
}

void Devices::remove_device(std::array<std::byte, 32> id, result_function<bool> cb) {
    async([this, id] { return _remove_device(id); }, std::move(cb));
}

bool Devices::remove_device(std::span<const std::byte, 32> id, await_t) {
    return jq().call_get([this, id] { return _remove_device(id); });
}

bool Devices::_remove_device(std::span<const std::byte, 32> id) {
    assert(on_loop());
    if (std::ranges::equal(id, self_id))
        throw std::invalid_argument{"remove_device: cannot remove this device itself"};

    auto c = conn();
    SQLite::Transaction tx{c.sql};

    if (!_member())
        return false;

    if (!c.prepared_maybe_get<int64_t>(
                "UPDATE devices SET state = ?, kicked_timestamp = ?, broadcast_needed = 1"
                " WHERE unique_id = ? AND state = ? RETURNING id",
                static_cast<int>(device::State::Kicked),
                epoch_seconds(clock_now_s()),
                id,
                static_cast<int>(device::State::Registered)))
        return false;

    // In the same transaction, so there is no moment at which the removal is recorded and the key
    // the removed device holds is still the one a push would treat as current.
    rotate_account_keys();
    tx.commit();

    log::info(cat, "Removed device {} from the group", oxenc::to_hex(id));
    _devices_changed = true;
    _flush_events();
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
        std::span<const std::array<std::byte, 32>> member_changes,
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
    if (state.membership != device::Membership::Unknown &&
        state.membership != _reported_membership) {
        _reported_membership = state.membership;
        report("membership_changed", [&] { events.membership_changed(state.membership); });
    }

    // A fork is news only to a device in a group: one outside any has nothing to be forked from.
    if (state.membership == device::Membership::InGroup)
        for (const auto& other : state.others)
            if (!other.dismissed && _announced_groups.insert(other.id.value).second)
                report("group_appeared", [&] { events.group_appeared(other.id); });

    return next_deadline;
}

void Devices::parse_device_messages(std::span<const SwarmMessage> messages, bool is_final) {
    for (const auto& msg : messages) {
        try {
            oxenc::bt_dict_consumer in{msg.data};
            auto type = in.require<std::string_view>("");
            if (type == "G") {
                _record_group(msg);
                receive_device_group_message(msg.data, msg.hash, msg.timestamp);
            } else if (type == "L")
                receive_link_request(msg.data, msg.hash, msg.expiry);
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

    // Pushed from here rather than from whatever dirtied the group, so that what goes out is built
    // on top of everything this fetch merged.  A local change made between fetches waits for the
    // next one, which is what stops two devices answering the same update with duelling pushes.
    push_device_group();
}

void Devices::parse_account_pubkeys(std::span<const SwarmMessage> messages, bool /*is_final*/) {
    if (messages.empty())
        return;

    // The x25519 pubkey for signature verification: session_id() is 0x05 || x25519_pub
    auto x25519_pub = core.globals.session_id().subspan<1>();

    auto c = conn();
    for (const auto& msg : messages) {
        try {
            oxenc::bt_dict_consumer in{msg.data};
            auto M = in.require_span<unsigned char, mlkem768::PUBLICKEYBYTES>("M");
            auto X = in.require_span<unsigned char, 32>("X");
            in.require_signature(
                    "~",
                    [&x25519_pub](std::span<const std::byte> body, std::span<const std::byte> sig) {
                        if (sig.size() != 64 ||
                            !xed25519::verify(sig.first<64>(), x25519_pub, body))
                            throw std::runtime_error{
                                    "Invalid account pubkey message: signature verification "
                                    "failed"};
                    });

            // Look up the key by indicator (indexed) then verify full pubkeys, and mark published.
            c.prepared_exec(
                    "UPDATE device_account_keys SET published = 1"
                    " WHERE key_indicator = ? AND pubkey_mlkem768 = ? AND pubkey_x25519 = ?",
                    M.first<2>(),
                    M,
                    X);
        } catch (const std::exception& e) {
            log::warning(cat, "Ignoring malformed account pubkey message: {}", e.what());
        }
    }
}

static const std::string NEEDS_PUSH_SQL =
        "SELECT"
        // device_group: we are registered AND (own seqno dirty OR broadcast needed OR
        // undistributed account key)
        " CASE WHEN EXISTS("
        "   SELECT 1 FROM devices WHERE unique_id = ? AND state = {0}"
        " ) THEN ("
        "   (SELECT pushed_seqno IS NULL OR seqno > pushed_seqno"
        "    FROM devices WHERE unique_id = ?)"
        "   OR EXISTS(SELECT 1 FROM devices WHERE broadcast_needed)"
        "   OR EXISTS(SELECT 1 FROM device_account_keys WHERE NOT distributed)"
        " ) ELSE 0 END,"
        // account_pubkey: the current active account key has not yet been confirmed on the swarm
        " EXISTS(SELECT 1 FROM device_account_keys WHERE rotated IS NULL AND NOT published)"_format(
                static_cast<int>(device::State::Registered));

Devices::NeedsPush Devices::needs_push() {
    auto c = conn();
    auto [dg, ap] = c.prepared_get<int, int>(NEEDS_PUSH_SQL, self_id, self_id);
    // Not for a group that has moved on without us: we cannot read what it holds now, and would
    // push a snapshot of what it held before.
    return {.device_group = bool(dg) && !_displaced(), .account_pubkey = bool(ap)};
}

void Devices::mark_device_group_pushed(const DeviceGroupPush& push, std::string hash) {
    auto c = conn();
    SQLite::Transaction tx{c.sql};
    c.prepared_exec("UPDATE devices SET pushed_seqno = ? WHERE unique_id = ?", push.seqno, self_id);

    // Our own group, seen as it is now in the swarm, without waiting for the next fetch to bring
    // the message back -- in the meantime another group alongside it would read as our having been
    // cut off.
    auto now = clock_now_ms();
    _record_group(
            {.data = push.message,
             .hash = hash,
             .timestamp = now,
             .expiry = now +
                       std::chrono::duration_cast<std::chrono::milliseconds>(DEVICE_GROUP_TTL)});

    // Gone from the swarm, so stop naming them.  Scoped to what this message carried: one merged
    // while the push was in flight was not deleted and is not superseded by it.
    if (!push.obsolete.empty())
        c.prepared_exec(
                "DELETE FROM device_group_merged WHERE hash IN ({})"_format(
                        sqlite::placeholders(push.obsolete.size())),
                sqlite::bind_each{push.obsolete});

    // Our own message is now the newest snapshot, and the next push supersedes it in turn -- by the
    // same rule as everyone else's, since what makes a snapshot redundant is that its contents have
    // been carried forward, not who wrote it.
    if (!hash.empty())
        c.prepared_exec(
                "INSERT INTO device_group_merged (hash) VALUES (?) ON CONFLICT DO NOTHING", hash);

    if (!push.broadcast.empty())
        c.prepared_exec(
                "UPDATE devices SET broadcast_needed = 0 WHERE unique_id IN ({})"_format(
                        sqlite::placeholders(push.broadcast.size())),
                sqlite::bind_each{push.broadcast});

    if (!push.keys.empty())
        c.prepared_exec(
                "UPDATE device_account_keys SET distributed = 1 WHERE id IN ({})"_format(
                        sqlite::placeholders(push.keys.size())),
                sqlite::bind_each{push.keys});

    tx.commit();
}

void Devices::push_device_group() {
    if (_push_in_flight)
        return;
    if (!needs_push().device_group)
        return;

    DeviceGroupPush push;
    try {
        push = build_device_group_message();
    } catch (const std::exception& e) {
        log::warning(cat, "Not pushing device group: {}", e.what());
        return;
    }

    std::vector<SwarmStore> stores;
    stores.push_back(
            {.ns = config::Namespace::Devices,
             .data = push.message,
             .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(DEVICE_GROUP_TTL)});

    _push_in_flight = true;

    // Copied out before the call rather than passed as `push.obsolete`: the callback below captures
    // `push` by move, and the order the two arguments are evaluated in is unspecified, so reading
    // it inline can hand over an empty list from an already-moved-from struct.
    auto obsolete = push.obsolete;

    core._swarm_push(
            std::move(stores),
            std::move(obsolete),
            [this, alive = std::weak_ptr<int>{_alive}, push = std::move(push)](
                    std::optional<std::vector<SwarmStoreResult>> results) {
                if (alive.expired())
                    return;
                _push_in_flight = false;

                if (!results || results->empty() || !results->front().stored) {
                    log::warning(cat, "Device group push was not stored; leaving it owed");
                    return;
                }

                mark_device_group_pushed(push, std::move(results->front().hash));
            });
}

std::optional<std::chrono::system_clock::time_point> Devices::next_account_rotation() {
    auto c = conn();
    SQLite::Transaction tx{c.sql};

    if (!_member())
        return std::nullopt;

    int64_t t_created = 0;
    std::optional<cleared_b32> active_seed;
    for (auto [created, seed] : c.prepared_results<int64_t, sqlite::blobn<32>>(
                 "SELECT created, seed FROM device_account_keys"
                 " WHERE rotated IS NULL ORDER BY created DESC LIMIT 1")) {
        t_created = created;
        std::memcpy(active_seed.emplace().data(), seed.data(), seed.size());
    }
    if (!active_seed)
        return std::nullopt;

    auto N = c.prepared_get<int64_t>(
            "SELECT count(*) FROM devices WHERE state = ?",
            static_cast<int>(device::State::Registered));

    tx.commit();

    // u is a per-device uniform random value in [0,1], derived deterministically from the device
    // ID and current account key seed so that each device independently computes a consistent
    // rotation schedule.
    std::array<std::byte, 8> hash_out;
    hash::blake2b_key_pers(hash_out, *active_seed, PERS_ACC_KEY_ROT, self_id);
    double u = oxenc::load_little_to_host<uint64_t>(hash_out.data()) / 0x1p64;

    // With N registered devices, the minimum of their N individual offsets is uniformly
    // distributed in [PERIOD - WINDOW/2, PERIOD + WINDOW/2].
    auto offset = std::chrono::duration_cast<std::chrono::system_clock::duration>(
            (ACCOUNT_KEY_ROTATION_PERIOD - ACCOUNT_KEY_ROTATION_WINDOW / 2) +
            ACCOUNT_KEY_ROTATION_WINDOW * (1.0 - std::pow(u, static_cast<double>(N))));

    return std::chrono::sys_seconds{std::chrono::seconds{t_created}} + offset;
}

std::optional<std::chrono::system_clock::time_point> Devices::next_device_rotation() {
    // TODO: implement device key rotation scheduling
    return std::nullopt;
}

Devices::DeviceGroupPush Devices::build_device_group_message() {
    // One query for the whole group, so the seqno we report is the one the payload was built from.
    // Reading our own row separately would let an update_info() land between the two and have the
    // push confirm a seqno that is not what went out.
    auto devs = devices(true, true, true);

    auto self = devs.find(self_id);
    if (self == devs.end() || self->second.state != device::State::Registered)
        throw std::logic_error{"Cannot build device group message: this device is not registered"};

    DeviceGroupPush push;
    push.seqno = self->second.seqno;

    // Read in the same breath as the payload, so that what the confirm clears is what the message
    // actually contains rather than whatever is owed by the time the swarm answers.
    auto c = conn();
    for (auto id : c.prepared_results<sqlite::blob_guts<std::array<std::byte, 32>>>(
                 "SELECT unique_id FROM devices WHERE broadcast_needed"))
        push.broadcast.push_back(id);
    for (auto id :
         c.prepared_results<int64_t>("SELECT id FROM device_account_keys WHERE NOT distributed"))
        push.keys.push_back(id);
    for (auto hash : c.prepared_results<std::string>("SELECT hash FROM device_group_merged"))
        push.obsolete.push_back(std::move(hash));

    push.message = encrypt_device_data(devs);
    return push;
}

std::vector<std::byte> Devices::build_account_pubkey_message() {
    auto keys = active_account_keys();
    if (keys.empty())
        throw std::runtime_error{"build_account_pubkey_message: no active account keys"};
    const auto& k = keys.front();

    std::vector<std::byte> out(
            2                             // outer dict d...e
            + 3 + bt_bytes_encoded(1184)  // "1:M" + mlkem768_pub
            + 3 + bt_bytes_encoded(32)    // "1:X" + x25519_pub
            + 3 + bt_bytes_encoded(64)    // "1:~" + XEd25519 signature
    );

    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};
    o.append("M", k.mlkem768_pub);
    o.append("X", k.x25519_pub);
    o.append_signature("~", [seed = core.globals.account_seed()](std::span<const std::byte> body) {
        return xed25519::sign(seed.x25519_key(), body);
    });

    assert(o.view().size() == out.size());  // Ensure we calculated exactly the right size above
    return out;
}

}  // namespace session::core
