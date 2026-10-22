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
#include <session/config/encrypt.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/link_sas.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/crypto/mlkem768.hpp>
#include <session/crypto/x25519.hpp>
#include <session/encrypt.hpp>
#include <session/format.hpp>
#include <session/hash.hpp>
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
    active_account_keys();  // Mints the account's first shared seed if there is not one yet.

    auto c = conn();
    auto tx = c.begin_immediate();

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
    auto tx = c.begin_immediate();

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

    auto c = conn();
    c.prepared_exec(
            "INSERT INTO device_account_keys (created, seed, pubkey_mlkem768, pubkey_x25519)"
            " VALUES (?, ?, ?, ?)",
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
    auto tx = c.begin_immediate();

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
                       pubkey_x25519 = excluded.pubkey_x25519
                   WHERE (excluded.state, excluded.seqno) > (state, seqno)
                   RETURNING id)",
                info.id,
                static_cast<int>(info.state),
                info.seqno,
                info.timestamp.time_since_epoch().count(),
                info.encoded_type(),
                info.description,
                ver,
                info.pk_mlkem768,
                info.pk_x25519);

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
    // `include_unregistered` covers Kicked as well as Unregistered: the two were one state until
    // the merge rules needed them apart, and a caller asking for devices that are not in the group
    // means both.  Separating them here is a caller-visible change worth making on its own.
    int state_mask = (include_registered ? 1 << static_cast<int>(device::State::Registered) : 0) |
                     (include_pending ? 1 << static_cast<int>(device::State::Pending) : 0) |
                     (include_unregistered ? (1 << static_cast<int>(device::State::Unregistered)) |
                                                     (1 << static_cast<int>(device::State::Kicked))
                                           : 0);
    if (state_mask == 0)
        return {};

    auto c = conn();
    // Deferred, not begin_immediate(): this only reads, for one consistent snapshot.
    auto tx = c.begin();
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
    auto tx = c.begin_immediate();

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
                } else if (info.state == device::State::Kicked) {
                    // A kicked device goes in as a bare timestamp: that is how every other device
                    // learns of the removal, since a record merely absent from a message means
                    // "unchanged" rather than "removed".
                    //
                    // TODO: we should stop writing devices kicked a long time ago.  Pruning means
                    // dropping them from *this payload* and never from the table -- the budget is
                    // on what the message carries, a local row costs nothing, and forgetting one
                    // would lower its rank and let a stale group resurrect the device.
                    assert(info.kicked);
                    devs.append(id_sv, info.kicked->time_since_epoch().count());
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

    std::string encode_link_request_plaintext(
            std::span<const std::byte, 32> device_id, const device::Info& info) {
        oxenc::bt_dict_producer out;
        // "I" (device id) sorts before "i" (info dict)
        out.append("I", device_id);
        encode_device_info(out.append_dict("i"), info);
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

    // Decodes the plaintext bt-encoded device group payload.  The returned device map will include
    // both full device records and tombstoned devices: the latter have a mostly default-constructed
    // Info where only id, state (=State::Kicked), and kicked (=removal timestamp) are set.
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
                // An integer indicates a "device removed" timestamp, used to distinguish between
                // "device removed" and "I don't know about the device yet".  It gets pruned when
                // updating once it hits a certain age threshold.
                //
                // If the device wants to get re-added to the group then it must generate a new
                // device id.
                info.state = device::State::Kicked;
                info.kicked.emplace(std::chrono::seconds{devs.consume_integer<int64_t>()});
            } else {
                decode_one(info, devs.consume_dict_consumer(), device::State::Registered);
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

    // Values for the devices.processing column, set during batch message processing and cleared
    // after callbacks are fired at is_final.
    enum class Processing {
        LinkRequest = 1,  // new/updated link request received
        Registered = 2,   // device newly transitioned to Registered
        Removed = 3,      // device newly transitioned to Unregistered
    };

    constexpr std::string_view to_string(Processing p) {
        switch (p) {
            case Processing::LinkRequest: return "link-request";
            case Processing::Registered: return "registered";
            case Processing::Removed: return "removed";
        }
        return "unknown";
    }

    constexpr auto PERS_DEV_NONCE = "SessionDevDNonce"_b2b_pers;
    constexpr auto PERS_KEY_NONCE = "SessionDevKNonce"_b2b_pers;
    constexpr auto PERS_KEY_KEY = "SessionDevKeyKey"_b2b_pers;
    constexpr auto PERS_KEY_KEY_IDX = "SessionDevKeyIdx"_b2b_pers;
    constexpr auto PERS_ACC_KEY_ROT = "SessionAccKeyRot"_b2b_pers;

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

}  // namespace session::core

/// Logs a `Processing` as the word `to_string` gives for it.  Out here for the reason given at the
/// top of this file; `session::core::Processing` names the type because the unnamed namespace it
/// lives in is reachable from its enclosing namespace.
template <>
struct fmt::formatter<session::core::Processing, char> : fmt::formatter<std::string_view> {
    auto format(session::core::Processing p, fmt::format_context& ctx) const {
        return formatter<std::string_view>::format(to_string(p), ctx);
    }
};

namespace session::core {

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
            + 3 + bt_bytes_encoded(A.size())               // "1:A" + "32:...(A eph pk)..."
            + 3 + bt_bytes_encoded(ciphertext_raw.size())  // "1:C" + "NNNN:...(mlkem cts)..."
            + 3 + bt_bytes_encoded(enc_key_raw.size())     // "1:K" + "NNN:...(encrypted keys)..."
            + 3 + bt_bytes_encoded(enc_devices.size())     // "1:d" + "MMMM:...(enc device info)..."
            + 3 + bt_bytes_encoded(64)                     // "1:~" + "64:...(Ed25519 signature)..."
    );

    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};

    o.append("", "G");
    o.append("A", A);
    o.append("C", ciphertext_raw);
    o.append("K", enc_key_raw);
    o.append("d", enc_devices);
    o.append_signature("~", [seed = core.globals.account_seed()](std::span<const std::byte> body) {
        return ed25519::sign(seed.ed25519_secret(), body);
    });

    assert(o.view().size() == out.size());  // Ensure we calculated exactly the right size above

    return out;
}

// Prebuilt SQL with Processing/State enum values embedded as literals rather than parameters.
// Records a device as kicked, inserting a bare tombstone row if we hold no record of it.
//
// The insert half is what makes a removal durable for a device that joined after it: an update
// alone matches nothing, stores nothing, and leaves that device free to accept the removed one back
// into the group.  A tombstone needs no details to do its job -- rank alone settles the merge -- so
// the columns the schema requires are filled with zeroes and the seqno left at 0, which no record
// off the wire can be.
//
// `processing` is set only where the device was Registered: a removal is news to the application
// only if we thought the device was a member, and a tombstone for one we never knew is not.
static const std::string KICK_DEVICE_SQL =
        "INSERT INTO devices"
        " (unique_id, state, seqno, timestamp, device_type, description, version,"
        "  pubkey_mlkem768, pubkey_x25519, kicked_timestamp)"
        " VALUES (?2, {0}, 0, ?1, '', '', 0, zeroblob(1184), zeroblob(32), ?1)"
        " ON CONFLICT(unique_id) DO UPDATE SET"
        "     state = {0}, kicked_timestamp = excluded.kicked_timestamp,"
        "     processing = CASE WHEN state = {1} THEN {2} ELSE processing END,"
        "     broadcast_needed = CASE WHEN state = {1} THEN 1 ELSE broadcast_needed END"_format(
                static_cast<int>(device::State::Kicked),
                static_cast<int>(device::State::Registered),
                static_cast<int>(Processing::Removed));

static const std::string REGISTER_DEVICE_SQL =
        "UPDATE devices SET processing = {}, broadcast_needed = 1 WHERE id = ?"_format(
                static_cast<int>(Processing::Registered));

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
static const std::string REASSERT_KICK_SQL =
        "UPDATE devices SET kicked_timestamp = ?, broadcast_needed = 1 WHERE unique_id = ?";

void Devices::receive_device_group_message(std::span<const std::byte> data) {
    GroupPayload payload;
    try {
        auto raw = decrypt_device_data(std::as_bytes(data));
        payload = decode_group_payload(raw);
    } catch (const device::decryption_failed& e) {
        log::warning(cat, "Ignoring incoming device group message: {}", e.what());
        return;
    }

    auto c = conn();
    auto tx = c.begin_immediate();

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

    for (const auto& [id, info] : payload.devices) {
        if (info.state == device::State::Kicked) {
            // Whatever details we already hold are kept; only the state and the timestamp move.  A
            // device we have never heard of gets a bare tombstone -- see KICK_DEVICE_SQL.
            assert(info.kicked);
            c.prepared_exec(KICK_DEVICE_SQL, info.kicked->time_since_epoch().count(), id);
            continue;
        }

        // A removal is one-way: a device we hold a tombstone for cannot be returned to the group by
        // a record in a message, only by a fresh link request under a new device id.  Anything
        // claiming otherwise is either a device that was removed and is re-adding itself -- it
        // still holds the account seed, so it can sign and push whatever it likes -- or a device
        // relaying such a record.  Either way the answer is to restate the removal rather than to
        // adopt it.
        //
        // Asks the state, which now says only this: `Kicked` is removal and nothing else, where
        // `Unregistered` covers a device that was never in the group -- our own row before the
        // group is established, and an ignored link request -- both of which must still be able to
        // register.
        auto kicked = c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", id)
                              .value_or(-1) == static_cast<int>(device::State::Kicked);
        if (kicked) {
            log::warning(
                    cat,
                    "Device group message tried to restore removed device {}; restating removal",
                    oxenc::to_hex(id));
            c.prepared_exec(REASSERT_KICK_SQL, epoch_seconds(clock_now_s()), id);
            continue;
        }

        // Check state before upsert to detect a registration transition.
        bool was_registered =
                c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", id)
                        .value_or(-1) == static_cast<int>(device::State::Registered);

        auto dev_id = upsert_device_info(c, info);
        if (!dev_id)
            continue;

        // Mark as newly registered only on a state transition (not for info-only updates).
        if (!was_registered)
            c.prepared_exec(REGISTER_DEVICE_SQL, *dev_id);
    }

    tx.commit();
}

void Devices::build_link_request(result_function<LinkRequestResult> cb) {
    async([this] { return _build_link_request(); }, std::move(cb));
}

Devices::LinkRequestResult Devices::build_link_request(await_t) {
    return jq().call_get([this] { return _build_link_request(); });
}

Devices::LinkRequestResult Devices::_build_link_request() {
    assert(on_loop());
    auto [info, is_registered] = _device_info();

    if (is_registered)
        throw std::logic_error{
                "build_link_request() called on a device that is already registered in the device "
                "group"};

    info.id = self_id;
    info.seqno++;
    info.timestamp = clock_now_s();

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

    // Upsert our own device row with the updated seqno, timestamp, and pubkeys.  The pending link
    // request is detectable via state=Pending on our own row; needs_push() detects dirty state via
    // the seqno increment above exceeding pushed_seqno.
    auto c = conn();
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

    auto plaintext = encode_link_request_plaintext(self_id, info);
    auto sas = link_request_sas(to_span<std::byte>(plaintext));

    // Encrypt the plaintext
    std::vector<std::byte> encrypted(plaintext.size() + config::ENCRYPT_DATA_OVERHEAD);
    std::memcpy(encrypted.data(), plaintext.data(), plaintext.size());
    auto seed = core.globals.account_seed();
    config::encrypt_prealloced(encrypted, seed.seed(), "link-request");

    // Wrap in outer bt-dict: {"": "L", "L": <encrypted>}
    std::vector<std::byte> out(
            2                                         // Outer "d" ... "e" delimiters
            + 5                                       // "0:" + "1:L" (message type indicator)
            + 3 + bt_bytes_encoded(encrypted.size())  // "1:L" + "NNN:...(encrypted blob)..."
    );
    oxenc::bt_dict_producer o{reinterpret_cast<char*>(out.data()), out.size()};
    o.append("", "L");
    o.append("L", std::span<const std::byte>{encrypted});
    assert(o.view().size() == out.size());

    return {std::move(out), sas};
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

void Devices::receive_link_request(std::span<const std::byte> data) {
    // Parse outer bt-dict: {"": "L", "L": <encrypted>}
    oxenc::bt_dict_consumer outer{data};
    outer.require<std::string_view>("");  // skip type indicator
    auto encrypted = outer.require_span<std::byte>("L");

    // Decrypt using the account seed
    std::vector<std::byte> plaintext;
    try {
        auto seed = core.globals.account_seed();
        plaintext = config::decrypt(encrypted, seed.seed(), "link-request");
    } catch (const config::decrypt_error& e) {
        log::warning(cat, "Ignoring incoming link request: decryption failed: {}", e.what());
        return;
    }

    // Parse plaintext: {"I": <32-byte device id>, "i": {device info dict}}
    device::Info info;
    try {
        oxenc::bt_dict_consumer pt{std::span<const std::byte>{plaintext}};
        auto in_id = pt.require_span<unsigned char, 32>("I");
        std::memcpy(info.id.data(), in_id.data(), info.id.size());

        // Skip any unknown keys between "I" and "i"
        oxenc::bt_dict extra_outer;
        while (!pt.is_finished() && pt.key() < "i")
            consume_extra(pt, extra_outer);
        if (pt.is_finished() || pt.key() != "i")
            throw std::runtime_error{"missing 'i' device info dict"};
        decode_one(info, pt.consume_dict_consumer(), device::State::Pending);
    } catch (const std::exception& e) {
        log::warning(cat, "Ignoring incoming link request: failed to parse: {}", e.what());
        return;
    }

    auto c = conn();

    // Reject if already registered or unregistered; only Pending (or absent) is valid
    auto existing_state =
            c.prepared_maybe_get<int>("SELECT state FROM devices WHERE unique_id = ?", info.id)
                    .value_or(-1);
    if (existing_state != -1 && existing_state != static_cast<int>(device::State::Pending)) {
        log::debug(
                cat,
                "Ignoring link request from {}: device already in state {}",
                oxenc::to_hex(info.id),
                existing_state);
        return;
    }

    auto tx = c.begin_immediate();

    auto dev_id = upsert_device_info(c, info);
    if (!dev_id) {
        log::debug(
                cat,
                "Ignoring link request from {}: rejected by seqno guard",
                oxenc::to_hex(info.id));
        return;
    }

    auto sas_seed = derive_sas_seed(as_span<std::byte>(std::span{plaintext}));

    c.prepared_exec(
            R"(INSERT INTO device_link_requests (device, received_at, sas_seed)
               VALUES (?, ?, ?)
               ON CONFLICT(device) DO UPDATE SET
                   received_at = excluded.received_at,
                   sas_seed = excluded.sas_seed)",
            *dev_id,
            epoch_seconds(clock_now_s()),
            sas_seed);

    // Set processing=LinkRequest only if not already set to a higher-priority value by a
    // concurrent device group message in the same batch
    c.prepared_exec(
            "UPDATE devices SET processing = ? WHERE id = ? AND processing IS NULL",
            static_cast<int>(Processing::LinkRequest),
            *dev_id);

    tx.commit();
}

void Devices::parse_device_messages(std::span<const SwarmMessage> messages, bool is_final) {
    for (const auto& msg : messages) {
        try {
            oxenc::bt_dict_consumer in{msg.data};
            auto type = in.require<std::string_view>("");
            if (type == "G")
                receive_device_group_message(msg.data);
            else if (type == "L")
                receive_link_request(msg.data);
            else
                log::warning(cat, "Ignoring device message with unknown type '{}'", type);
        } catch (const std::exception& e) {
            log::warning(cat, "Ignoring malformed device message: {}", e.what());
        }
    }

    if (!is_final)
        return;

    // Fire deferred callbacks for all devices with a pending processing state.  We collect first
    // to avoid nested statement conflicts during callback + processing-clear operations.
    struct ProcessingItem {
        int64_t row_id;
        std::array<std::byte, 32> id;
        Processing processing;
        device::Info info;
    };

    auto c = conn();
    std::vector<ProcessingItem> items;
    for (auto [row_id,
               raw_id,
               processing_int,
               state_int,
               seqno,
               timestamp,
               dtype,
               desc,
               ver,
               pk_ml,
               pk_x,
               kicked_ts] :
         c.prepared_results<
                 int64_t,
                 sqlite::blob_guts<std::array<std::byte, 32>>,
                 int,
                 int,
                 int,
                 int64_t,
                 std::string,
                 std::string,
                 int64_t,
                 sqlite::blobn<mlkem768::PUBLICKEYBYTES>,
                 sqlite::blobn<32>,
                 std::optional<int64_t>>(
                 "SELECT id, unique_id, processing, state, seqno, timestamp, device_type,"
                 "       description, version, pubkey_mlkem768, pubkey_x25519, kicked_timestamp"
                 " FROM devices WHERE processing IS NOT NULL ORDER BY unique_id")) {
        auto& item = items.emplace_back();
        item.row_id = row_id;
        item.id = raw_id;
        item.processing = static_cast<Processing>(processing_int);
        item.info = fill_device_info(
                raw_id,
                state_int,
                seqno,
                timestamp,
                std::move(dtype),
                std::move(desc),
                ver,
                pk_ml,
                pk_x);
        if (kicked_ts)
            item.info.kicked.emplace(std::chrono::seconds{*kicked_ts});
        load_device_extras(c, row_id, item.info);
    }

    // Non-const so a handler can take the info: each item reaches exactly one branch below, and
    // nothing after the switch reads `info` again.
    for (auto& item : items) {
        bool is_self = (item.id == self_id);
        try {
            switch (item.processing) {
                case Processing::LinkRequest:
                    if (auto& f = cb().device_link_request) {
                        auto [lr_id, sas_seed] = c.prepared_get<
                                int64_t,
                                sqlite::blob_guts<std::array<std::byte, 16>>>(
                                "SELECT id, sas_seed FROM device_link_requests WHERE device = ?",
                                item.row_id);
                        f(static_cast<int>(lr_id), std::move(item.info), sas_from_seed(sas_seed));
                    }
                    break;
                case Processing::Registered:
                    if (is_self) {
                        if (auto& f = cb().device_self_added)
                            f();
                    } else {
                        if (auto& f = cb().device_added) {
                            auto reqid =
                                    c.prepared_maybe_get<int64_t>(
                                             "SELECT id FROM device_link_requests WHERE device = ?",
                                             item.row_id)
                                            .value_or(0LL);
                            f(static_cast<int>(reqid), std::move(item.info));
                        }
                        // Clean up any link request row (whether callback was set or not)
                        c.prepared_exec(
                                "DELETE FROM device_link_requests WHERE device = ?", item.row_id);
                    }
                    break;
                case Processing::Removed:
                    if (is_self) {
                        if (auto& f = cb().device_self_removed)
                            f();
                    } else {
                        if (auto& f = cb().device_removed)
                            f(std::move(item.info));
                    }
                    break;
            }
            c.prepared_exec("UPDATE devices SET processing = NULL WHERE id = ?", item.row_id);
        } catch (const std::exception& e) {
            log::error(
                    cat,
                    "Exception in {} device callback for device {}: {}",
                    item.processing,
                    oxenc::to_hex(item.id),
                    e.what());
            // Don't clear processing so the callback will be retried
        }
    }

    // Prune stale link requests (older than 10 minutes)
    c.prepared_exec(
            "DELETE FROM device_link_requests WHERE received_at < ?",
            epoch_seconds(clock_now_s() - LINK_REQUEST_MAX_AGE));
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
    return {.device_group = bool(dg), .account_pubkey = bool(ap)};
}

void Devices::mark_device_group_pushed(int64_t seqno) {
    auto c = conn();
    auto tx = c.begin_immediate();
    c.prepared_exec("UPDATE devices SET pushed_seqno = ? WHERE unique_id = ?", seqno, self_id);
    c.prepared_exec("UPDATE devices SET broadcast_needed = 0");
    c.prepared_exec("UPDATE device_account_keys SET distributed = 1");
    tx.commit();
}

std::optional<std::chrono::system_clock::time_point> Devices::next_account_rotation() {
    auto c = conn();
    // Deferred, not begin_immediate(): this only reads, for one consistent snapshot.
    auto tx = c.begin();

    if (!c.prepared_maybe_get<int>(
                "SELECT 1 FROM devices WHERE unique_id = ? AND state = ?",
                self_id,
                static_cast<int>(device::State::Registered)))
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

    return {encrypt_device_data(devs), self->second.seqno};
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
