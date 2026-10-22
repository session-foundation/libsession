#include <oxenc/hex.h>
#include <sodium/utils.h>

#include <cassert>
#include <concepts>
#include <oxen/log.hpp>
#include <session/core.hpp>
#include <session/core/globals.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/random.hpp>
#include <session/sodium_array.hpp>
#include <session/sqlite.hpp>

namespace session::core {

namespace log = oxen::log;
auto cat = log::Cat("core.gbl");

using namespace std::literals;

static const std::string GET_ONE = "SELECT value FROM globals WHERE key = ? AND typeof(value) = ?"s;

std::optional<int64_t> Globals::get_integer(std::string_view key) {
    return conn().prepared_maybe_get<int64_t>(GET_ONE, key, "integer");
}
std::optional<double> Globals::get_real(std::string_view key) {
    return conn().prepared_maybe_get<double>(GET_ONE, key, "real");
}
std::optional<std::string> Globals::get_text(std::string_view key) {
    return conn().prepared_maybe_get<std::string>(GET_ONE, key, "text");
}
std::optional<std::vector<std::byte>> Globals::get_blob(std::string_view key) {
    std::optional<std::vector<std::byte>> result;
    auto c = conn();
    auto st = c.prepared_bind(GET_ONE, key, "blob");
    if (st->executeStep()) {
        auto data = sqlite::get<sqlite::blob>(st);
        result.emplace().reserve(data.size());
        result->assign(data.begin(), data.end());
    }
    return result;
}
std::optional<session::secure_buffer> Globals::get_blob_secure(std::string_view key) {
    std::optional<secure_buffer> result;
    auto c = conn();
    auto st = c.prepared_bind(GET_ONE, key, "blob");
    if (st->executeStep())
        result.emplace(sqlite::get<sqlite::blob>(st));
    return result;
}
bool Globals::get_blob_to(std::string_view key, std::span<std::byte> to) {
    auto c = conn();
    auto st = c.prepared_bind(GET_ONE, key, "blob");
    if (st->executeStep()) {
        if (auto data = sqlite::get<sqlite::blob>(st); data.size() == to.size()) {
            std::memcpy(to.data(), data.data(), to.size());
            return true;
        }
    }
    return false;
}

static const std::string GET_ANY = "SELECT value, typeof(value) FROM globals WHERE key = ?"s;

template <std::invocable<sqlite::blob> BlobLoader>
static auto get_variant_impl(sqlite::Connection&& c, std::string_view key, BlobLoader&& b) {

    using blob_t = decltype(b(std::declval<sqlite::blob>()));

    std::variant<std::monostate, int64_t, double, std::string, blob_t> result;

    auto st = c.prepared_bind(GET_ANY, key);
    if (st->executeStep()) {
        auto val = st->getColumn(0);
        auto type = static_cast<std::string>(st->getColumn(1));
        if (type == "int")
            result.template emplace<int64_t>(std::move(val));
        else if (type == "text")
            result.template emplace<std::string>(std::move(val));
        else if (type == "blob")
            result = b(sqlite::blob{std::move(val)});
        else if (type == "real")
            result.template emplace<double>(std::move(val));
    }

    return result;
}

std::variant<std::monostate, int64_t, double, std::string, std::vector<std::byte>> Globals::get(
        std::string_view key) {
    return get_variant_impl(conn(), key, [](sqlite::blob data) {
        std::vector<std::byte> v;
        v.reserve(data.size());
        v.assign(data.begin(), data.end());
        return v;
    });
}

std::variant<std::monostate, int64_t, double, std::string, session::secure_buffer>
Globals::get_secure(std::string_view key) {
    return get_variant_impl(conn(), key, [](sqlite::blob data) { return secure_buffer{data}; });
}

static const std::string SET_VAL =
        "INSERT INTO globals (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value"s;

void Globals::set(std::string_view key, int64_t integer) {
    conn().prepared_exec(SET_VAL, key, integer);
}
void Globals::set(std::string_view key, double real) {
    conn().prepared_exec(SET_VAL, key, real);
}
void Globals::set(std::string_view key, std::string_view text) {
    conn().prepared_exec(SET_VAL, key, text);
}
void Globals::set(std::string_view key, std::span<const std::byte> blob) {
    conn().prepared_exec(SET_VAL, key, blob);
}

bool Globals::erase(std::string_view key) {
    return conn().prepared_exec("DELETE FROM globals WHERE key = ?"s, key) > 0;
}

void Globals::_adopt_seed(const cleared_b32& seed, bool persist) {
    // Everything below this line is cached state that Core's loop reads while polling, rewritten
    // in place: the secure buffer reallocates and `_session_id_hex` is reassigned.  Reached from
    // init() during construction, which on_loop() excuses, and otherwise only from the two public
    // account methods.
    assert(on_loop());

    // Layout: [ed25519_sk(64) | x25519_sk(32)] = 96 bytes
    auto rw = _account_seed.resize(96);

    ed25519::seed_keypair(_pubkey_ed25519, rw.buf.first<64>(), seed);
    ed25519::sk_to_x25519(rw.buf.last<32>(), seed);

    ed25519::pk_to_x25519(_pubkey_x25519, _pubkey_ed25519);

    _session_id[0] = std::byte{0x05};
    std::copy(_pubkey_x25519.begin(), _pubkey_x25519.end(), _session_id.data() + 1);
    _session_id_hex = oxenc::to_hex(_session_id);

    if (persist)
        set("_seed", rw.buf.first(32));

    _have_account = true;

    log::info(cat, "Initialized with Session ID: {}", _session_id_hex);
}

// Generates the 16-byte/128-bit seed that Session accounts use: 16 random bytes followed by 16
// zeros.
// FIXME: we should allow full 32-byte seeds here.
static cleared_b32 generate_seed() {
    cleared_b32 seed;
    random::fill(std::span{seed}.first<16>());
    std::memset(seed.data() + 16, 0, 16);
    return seed;
}

void Globals::init() {
    auto c = conn();
    auto tx = c.begin_immediate();

    cleared_b32 seed;
    if (get_blob_to("_seed", seed)) {
        _adopt_seed(seed, false);
    } else if (_predefined_seed) {
        _adopt_seed(*_predefined_seed, true);
        _predefined_seed.reset();  // Clear now that it has been consumed
    } else if (!_defer_account) {
        log::info(cat, "Generated new Session account seed");
        _adopt_seed(generate_seed(), true);
        core.configs.initialise_new_account();
        _mark_new_account();
    } else {
        // defer_account, and nothing stored: the application chooses an identity before this
        // account can do anything.  Nothing else in Core needs the seed at init time -- Devices
        // only stores its own device id, and polling does not start until a network is attached.
        log::info(cat, "Opened with no account; awaiting create_account() or restore_account()");
    }

    tx.commit();
}

void Globals::create_account(result_function<> cb) {
    async([this] { _create_account(); }, std::move(cb));
}

void Globals::create_account(await_t) {
    jq().call_get([this] { _create_account(); });
}

void Globals::_create_account() {
    assert(on_loop());
    if (_have_account)
        throw std::logic_error{"This account already has an identity"};
    auto c = conn();
    auto tx = c.begin_immediate();
    log::info(cat, "Generated new Session account seed");
    _adopt_seed(generate_seed(), true);
    core.configs.initialise_new_account();
    _mark_new_account();
    tx.commit();

    // After the commit, not inside it: establishing the group opens transactions of its own, and
    // this connection is thread-unique, so nesting would fail.  Safe to defer -- the flag written
    // above is what survives a crash here, and Devices::init() acts on it next time.
    core.devices.establish_group();
}

// A generated account owes a device group; a restored one does not, since it may already have one
// belonging to devices that are simply offline.  Recorded rather than acted on here because Devices
// initialises after this component and has no device id yet during init.
void Globals::_mark_new_account() {
    core.devices._mark_group_owed();
}

void Globals::restore_account(predefined_seed seed, result_function<> cb) {
    async([this, seed = std::move(seed)] { _restore_account(seed); }, std::move(cb));
}

void Globals::restore_account(const predefined_seed& seed, await_t) {
    jq().call_get([this, &seed] { _restore_account(seed); });
}

void Globals::_restore_account(const predefined_seed& seed) {
    assert(on_loop());
    if (_have_account)
        throw std::logic_error{"This account already has an identity"};
    auto c = conn();
    auto tx = c.begin_immediate();
    _adopt_seed(seed.bytes, true);
    tx.commit();
}

mnemonics::secure_mnemonic Globals::seed_mnemonic(const mnemonics::Mnemonics& lang, bool force_24) {
    _require_account();
    auto seed = _account_seed.access();
    // _account_seed stores the 96-byte key material; the first 32 bytes are the account seed.
    // A Session account uses 128-bit entropy when the last 16 bytes of that seed are all zero;
    // in that case we encode only the first 16 bytes.
    auto seed32 = seed.buf.first(32);
    bool is_128bit = !force_24 &&
                     sodium_memcmp(seed32.data() + 16, std::array<std::byte, 16>{}.data(), 16) == 0;
    return mnemonics::bytes_to_words(is_128bit ? seed32.first(16) : seed32, lang);
}

mnemonics::secure_mnemonic Globals::seed_mnemonic(std::string_view lang_name, bool force_24) {
    return seed_mnemonic(mnemonics::get_language(lang_name), force_24);
}

}  // namespace session::core
