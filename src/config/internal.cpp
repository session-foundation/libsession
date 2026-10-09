#include "internal.hpp"

#include <fmt/ranges.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/bt_value_producer.h>
#include <oxenc/hex.h>

#include <iterator>
#include <optional>
#include <oxen/log/format.hpp>

using namespace oxen::log::literals;

namespace session::config {

namespace {

    constexpr std::array all_session_id_prefixes = {
            session::SessionIDPrefix::standard,
            session::SessionIDPrefix::group,
            session::SessionIDPrefix::community_blinded_legacy,
            session::SessionIDPrefix::community_blinded,
            session::SessionIDPrefix::version_blinded,
            session::SessionIDPrefix::unblinded};

}  // namespace

void check_session_id(std::string_view session_id, std::string_view prefix) {
    if (!(session_id.size() == 64 + prefix.size() && oxenc::is_hex(session_id) &&
          session_id.substr(0, prefix.size()) == prefix))
        throw std::invalid_argument{
                "Invalid session ID: expected 66 hex digits starting with " + std::string{prefix} +
                "; got " + std::string{session_id}};
}

SessionIDPrefix get_session_id_prefix(std::string_view id) {
    if (oxenc::is_hex(id) && id.size() == 66) {
        for (auto prefix : all_session_id_prefixes) {
            auto prefix_str = to_string(prefix);

            if ((id.size() == 64 + prefix_str.size() &&
                 id.substr(0, prefix_str.size()) == prefix_str))
                return prefix;
        }
    }

    // If we get here then the id wasn't any of the currently defined prefixes
    throw std::invalid_argument{fmt::format(
            "Invalid session ID: expected 66 hex digits starting with one of [{}]; got {}",
            fmt::join(all_session_id_prefixes, ", "),
            id)};
}

std::string session_id_to_bytes(std::string_view session_id, std::string_view prefix) {
    check_session_id(session_id, prefix);
    return oxenc::from_hex(session_id);
}

std::array<unsigned char, 32> session_id_pk(std::string_view session_id, std::string_view prefix) {
    check_session_id(session_id, prefix);
    std::array<unsigned char, 32> pk;
    session_id.remove_prefix(2);
    oxenc::from_hex(session_id.begin(), session_id.end(), pk.begin());
    return pk;
}

void check_encoded_pubkey(std::string_view pk) {
    if (!((pk.size() == 64 && oxenc::is_hex(pk)) ||
          ((pk.size() == 43 || (pk.size() == 44 && pk.back() == '=')) && oxenc::is_base64(pk)) ||
          (pk.size() == 52 && oxenc::is_base32z(pk))))
        throw std::invalid_argument{"Invalid encoded pubkey: expected hex, base32z or base64"};
}

std::vector<unsigned char> decode_pubkey(std::string_view pk) {
    std::vector<unsigned char> pubkey;
    pubkey.reserve(32);
    if (pk.size() == 64 && oxenc::is_hex(pk))
        oxenc::from_hex(pk.begin(), pk.end(), std::back_inserter(pubkey));
    else if ((pk.size() == 43 || (pk.size() == 44 && pk.back() == '=')) && oxenc::is_base64(pk))
        oxenc::from_base64(pk.begin(), pk.end(), std::back_inserter(pubkey));
    else if (pk.size() == 52 && oxenc::is_base32z(pk))
        oxenc::from_base32z(pk.begin(), pk.end(), std::back_inserter(pubkey));
    else
        throw std::invalid_argument{"Invalid encoded pubkey: expected hex, base32z or base64"};
    return pubkey;
}

void make_lc(std::string& s) {
    for (auto& c : s)
        if (c >= 'A' && c <= 'Z')
            c += ('a' - 'A');
}

template <typename Scalar>
const Scalar* maybe_scalar(const session::config::dict& d, const char* key) {
    if (auto it = d.find(key); it != d.end())
        if (auto* sc = std::get_if<session::config::scalar>(&it->second))
            if (auto* i = std::get_if<Scalar>(sc))
                return i;
    return nullptr;
}

const session::config::set* maybe_set(const session::config::dict& d, const char* key) {
    if (auto it = d.find(key); it != d.end())
        if (auto* s = std::get_if<session::config::set>(&it->second))
            return s;
    return nullptr;
}

std::optional<int64_t> maybe_int(const session::config::dict& d, const char* key) {
    if (auto* i = maybe_scalar<int64_t>(d, key))
        return *i;
    return std::nullopt;
}

int64_t int_or_0(const session::config::dict& d, const char* key) {
    if (auto* i = maybe_scalar<int64_t>(d, key))
        return *i;
    return 0;
}

std::optional<std::chrono::sys_seconds> maybe_ts(const session::config::dict& d, const char* key) {
    std::optional<std::chrono::sys_seconds> result;
    if (auto* i = maybe_scalar<int64_t>(d, key))
        result.emplace(std::chrono::seconds{*i});
    return result;
}

std::optional<std::chrono::sys_time<std::chrono::milliseconds>> maybe_ts_ms(
        const session::config::dict& d, const char* key) {
    std::optional<std::chrono::sys_time<std::chrono::milliseconds>> result;
    if (auto* i = maybe_scalar<int64_t>(d, key))
        result.emplace(std::chrono::milliseconds{*i});
    return result;
}

std::chrono::sys_seconds ts_or_epoch(const session::config::dict& d, const char* key) {
    if (auto* i = maybe_scalar<int64_t>(d, key))
        return std::chrono::sys_seconds{std::chrono::seconds{*i}};
    return std::chrono::sys_seconds{};
}

std::optional<std::string> maybe_string(const session::config::dict& d, const char* key) {
    if (auto* s = maybe_scalar<std::string>(d, key))
        return *s;
    return std::nullopt;
}

uint64_t bitset_from_set_of_int64_or_0(const session::config::set& s) {
    uint64_t result = 0;
    constexpr size_t bits_available = sizeof(result) * 8;
    for (auto& v : s) {
        auto* val = std::get_if<int64_t>(&v);
        if (val && (*val >= 0 && *val < bits_available))
            result |= (1ULL << *val);
    }
    return result;
}

void set_int64_set_from_bitset(ConfigBase::DictFieldProxy&& field, uint64_t bitset) {
    constexpr size_t bits_available = sizeof(bitset) * 8;
    for (size_t index = 0; index < bits_available; index++) {
        uint64_t bit = bitset & (1ULL << index);
        if (bit)
            field.set_insert(index);
        else
            field.set_erase(index);
    }
}

std::string string_or_empty(const session::config::dict& d, const char* key) {
    if (auto* s = maybe_scalar<std::string>(d, key))
        return *s;
    return ""s;
}

std::optional<std::string_view> maybe_sv(const session::config::dict& d, const char* key) {
    if (auto* s = maybe_scalar<std::string>(d, key))
        return *s;
    return std::nullopt;
}

std::string_view sv_or_empty(const session::config::dict& d, const char* key) {
    if (auto* s = maybe_scalar<std::string>(d, key))
        return *s;
    return ""sv;
}

std::optional<std::span<const unsigned char>> maybe_span(
        const session::config::dict& d, const char* key) {
    std::optional<std::span<const unsigned char>> ret;
    if (auto* s = maybe_scalar<std::string>(d, key))
        ret.emplace(reinterpret_cast<const unsigned char*>(s->data()), s->size());
    return ret;
}

std::optional<std::vector<unsigned char>> maybe_vector(
        const session::config::dict& d, const char* key) {
    std::optional<std::vector<unsigned char>> result;
    if (auto* s = maybe_scalar<std::string>(d, key))
        result.emplace(
                reinterpret_cast<const unsigned char*>(s->data()),
                reinterpret_cast<const unsigned char*>(s->data()) + s->size());
    return result;
}

void set_flag(ConfigBase::DictFieldProxy&& field, bool val) {
    if (val)
        field = 1;
    else
        field.erase();
}

void set_positive_int(ConfigBase::DictFieldProxy&& field, int64_t val) {
    if (val > 0)
        field = val;
    else
        field.erase();
}

void set_nonzero_int(ConfigBase::DictFieldProxy&& field, int64_t val) {
    if (val != 0)
        field = val;
    else
        field.erase();
}

void set_nonempty_str(ConfigBase::DictFieldProxy&& field, std::string val) {
    if (!val.empty())
        field = std::move(val);
    else
        field.erase();
}

void set_nonempty_str(ConfigBase::DictFieldProxy&& field, std::string_view val) {
    if (!val.empty())
        field = val;
    else
        field.erase();
}

/// Writes all the dict elements in `[it, E)` into `out`; E is whichever of `end` or an element with
/// a key >= `until` comes first.
oxenc::bt_dict::iterator append_unknown(
        oxenc::bt_dict_producer& out,
        oxenc::bt_dict::iterator it,
        oxenc::bt_dict::iterator end,
        std::string_view until) {
    for (; it != end && it->first < until; ++it)
        out.append_bt(it->first, it->second);

    assert(!(it != end && it->first == until));
    return it;
}

/// Extracts and unknown keys in the top-level dict into `unknown` that have keys (strictly)
/// between previous and until.
void load_unknowns(
        oxenc::bt_dict& unknown,
        oxenc::bt_dict_consumer& in,
        std::string_view previous,
        std::string_view until) {
    while (!in.is_finished() && in.key() < until) {
        std::string key{in.key()};
        if (key <= previous || (!unknown.empty() && key <= unknown.rbegin()->first))
            throw oxenc::bt_deserialize_invalid{"top-level keys are out of order"};
        if (in.is_string())
            unknown.emplace_hint(unknown.end(), std::move(key), in.consume_string());
        else if (in.is_negative_integer())
            unknown.emplace_hint(unknown.end(), std::move(key), in.consume_integer<int64_t>());
        else if (in.is_integer())
            unknown.emplace_hint(unknown.end(), std::move(key), in.consume_integer<uint64_t>());
        else if (in.is_list())
            unknown.emplace_hint(unknown.end(), std::move(key), in.consume_list());
        else if (in.is_dict())
            unknown.emplace_hint(unknown.end(), std::move(key), in.consume_dict());
        else
            throw oxenc::bt_deserialize_invalid{"invalid bencoded value type"};
    }
}
}  // namespace session::config
