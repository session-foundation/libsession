#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <session/mnemonics.hpp>
#include <session/network/key_types.hpp>
#include <session/secure_buffer.hpp>
#include <session/sodium_array.hpp>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "component.hpp"

namespace session::core {

class Core;
// Defined in core.hpp, which includes this header; only referenced here as a parameter type.
struct predefined_seed;

/// How much randomness a generated account seed carries, which fixes the length of its recovery
/// phrase.
enum class SeedSize {
    Bits128,  ///< 13 words: the upper half of the 32-byte seed is zero.
    Bits256,  ///< 25 words.
};

// Core component contains one-off global values that don't make sense storing in a table, typically
// because the value is highly special purpose or is only used in one single place.  If you ever
// find yourself wanting to put multiple values in here under the same key, that is a sign that you
// should not be using this class and should instead refactor to use proper table relations.
//
// A note on keys: to avoid conflicts, external users of these globals should use prefix names that
// are unlikely to conflict with other uses.  For example, "session_ios_dark_mode" is a decent name,
// but "pubkey" is a terrible one.  All internal libsession keys in this table begin with an
// underscore, and should never be accesses outside libsession itself.
//
/// Thrown when something requiring the account's identity is used before there is one.  Only
/// reachable when the Core was constructed with defer_account: without it, construction either
/// finds a seed, is given one, or generates one.
struct no_account : std::logic_error {
    no_account() :
            std::logic_error{
                    "This Session account has no identity yet; call create_account() or "
                    "restore_account() first"} {}
};

class Globals final : detail::CoreComponent {

  private:
    friend class Core;
    explicit Globals(Core& c) : detail::CoreComponent{c} {}

    void _require_account() const {
        if (!_have_account)
            throw no_account{};
    }

    // Holds the account seed; loaded during initialization (created if it doesn't exist).  A new
    // account seed is generated during initialization if the database doesn't contain one (e.g. if
    // brand new).
    //
    // Read-only access is available via the account_seed() method.
    session::secure_buffer _account_seed;
    network::ed25519_pubkey _pubkey_ed25519;
    network::x25519_pubkey _pubkey_x25519;
    std::array<std::byte, 33> _session_id;  // AKA pubkey_x25519 with a 0x05 byte prefix
    std::string _session_id_hex;            // hex encoding of _session_id, computed once in init()

    void init() override;

    // If set by the Core constructor before init(), used as the initial account seed when the
    // database does not yet contain one.  Cleared after use in init().
    std::optional<cleared_b32> _predefined_seed;

    // Set by the Core constructor from the defer_account option: suppresses generating an account
    // during init() when the database has none.
    bool _defer_account = false;

    // False between construction and the account being resolved, which only happens when
    // defer_account was given and the database held no seed.
    bool _have_account = false;

    // Derives and caches the key material for `seed`, and stores the seed if `persist`.
    void _adopt_seed(const cleared_b32& seed, bool persist);

    // Generates a seed of `size` and adopts it as a *new* account: one that starts its configs from
    // nothing and owes a device group.  A restored account gets neither -- it may already have a
    // group belonging to devices we have not met.  The group is only recorded as owed, because
    // Devices initialises after this component and has no device id yet during init.
    void _adopt_new_account(SeedSize size);

    // What both public forms of each dispatch onto the loop; each asserts it got there.
    void _create_account(SeedSize size);
    void _restore_account(const predefined_seed& seed);

  public:
    /// Whether this account has an identity yet.
    ///
    /// Only ever false when the Core was constructed with defer_account and the database held no
    /// seed.  Until it is true, everything needing the account -- session_id(), account_seed(),
    /// send_dm(), attaching a network -- throws no_account.
    ///
    /// Safe to read from any thread once the identity is settled, which is what the rest of this
    /// paragraph is about.  This and the accessors below read state that `create_account()` and
    /// `restore_account()` write, and nothing synchronises the two: an application that reads
    /// them while one of those is still in flight on the loop is racing itself.  Await the
    /// handler, or use the `await` form, and the question does not arise -- an identity never
    /// changes again once it exists.
    bool have_account() const { return _have_account; }

    /// Generates a fresh account and stores it.
    ///
    /// The only way to get a *new* account, whatever size of seed it wants.  Adopting a seed
    /// generated elsewhere through `restore_account` makes an account indistinguishable from a
    /// restored one, which is never given a device group of its own -- correctly, for a restore,
    /// but a new account then has no group and no device that could ever admit it to one.
    ///
    /// Two forms and no third: this rewrites the cached key material Core's loop reads, so it
    /// happens on the loop either way.  Code already there uses the `await` form and pays nothing,
    /// since `call_get` runs the job inline when it is already the loop thread.
    ///
    /// @throws std::logic_error if this account already has an identity: adopting a second one
    /// would orphan every message and key already stored against the first.
    void create_account(SeedSize size, result_function<> cb);
    void create_account(SeedSize size, await_t);

    /// Adopts an existing account seed, as typed from a recovery phrase or transferred from
    /// another device, and stores it.
    ///
    /// This is also the first half of linking a new device to an existing account: a link request
    /// is encrypted to the account root key, so the seed must be adopted before
    /// devices.request_link() can be called.
    ///
    /// The handler form takes the seed by value because it outlives the call: it is carried to the
    /// loop and zeroed with the job, rather than borrowed from a caller that has already returned.
    ///
    /// @throws std::logic_error if this account already has an identity.
    void restore_account(predefined_seed seed, result_function<> cb);
    void restore_account(const predefined_seed& seed, await_t);

    // Retrieval methods.  These query for the given key and, if the type matches, return the given
    // value.  You get back nullopt if the database key does not exist, or if it contains a value
    // of some other type.
    //
    // These, `set` and `erase` are the exception to the threading rule on the rest of this class:
    // each is one self-contained query against a connection the pool hands the calling thread, and
    // touches nothing cached.  An application may call them from wherever it likes, and gets
    // whatever SQLite's own locking gives it if two threads write the same key at once.
    std::optional<int64_t> get_integer(std::string_view key);
    std::optional<double> get_real(std::string_view key);
    std::optional<std::string> get_text(std::string_view key);
    std::optional<std::vector<std::byte>> get_blob(std::string_view key);
    // Same as get_blob, but allocates a libsodium secure buffer to old the value.
    //
    // Do not use this to access the "seed" value: that value is cached in the Core object and
    // accessible via CoreComponent::access_seed().
    std::optional<session::secure_buffer> get_blob_secure(std::string_view key);
    // Reads a fixed size blob into `to`.  If the database does not contain a BLOB value of byte
    // length `to.size()`, returns false; other writes the blob value to `to` and returns true.
    bool get_blob_to(std::string_view key, std::span<std::byte> to);

    // Retrieves the value of whatever type it currently contains.  Returns a std::monostate if the
    // database key is not set at all, otherwise of of the other variant values.
    std::variant<std::monostate, int64_t, double, std::string, std::vector<std::byte>> get(
            std::string_view key);
    std::variant<std::monostate, int64_t, double, std::string, session::secure_buffer> get_secure(
            std::string_view key);

    // Assignment.  If the database key already exists, this overwrites it.
    void set(std::string_view key, int64_t integer);
    void set(std::string_view key, double real);
    void set(std::string_view key, std::string_view text);
    void set(std::string_view key, std::span<const std::byte> blob);

    /// Removes a key from the globals table.
    ///
    /// Returns true if the key existed and was removed, false if it was not set in the first
    /// place.  Erasing a key that was never set is not an error.
    bool erase(std::string_view key);

    /// RAII accessor returned by account_seed().  Holds the underlying secure buffer open for
    /// reading while alive; the buffer becomes unreadable again when the last copy is destroyed.
    struct AccountSeedAccess {
      private:
        friend class Globals;
        explicit AccountSeedAccess(const session::secure_buffer::r_accessor& acc) : _acc{acc} {}
        session::secure_buffer::r_accessor _acc;

        auto buf() const { return _acc.buf.first<96>(); }

      public:
        /// The raw 32-byte account seed (identical to ed25519_secret().first<32>()).
        std::span<const std::byte, 32> seed() const& { return buf().first<32>(); }
        std::span<const std::byte, 32> seed() const&& = delete;
        /// The 64-byte Ed25519 secret key in libsodium format (seed || pubkey).
        std::span<const std::byte, 64> ed25519_secret() const& { return buf().first<64>(); }
        std::span<const std::byte, 64> ed25519_secret() const&& = delete;
        /// The 32-byte X25519 secret key derived from the account seed.  This is also the clamped
        /// private scalar of the Ed25519 key, usable for advanced scalar-multiplication operations.
        std::span<const std::byte, 32> x25519_key() const& { return buf().last<32>(); }
        std::span<const std::byte, 32> x25519_key() const&& = delete;
    };

    // Each of these needs an identity, so each throws no_account when there is not one yet.  That
    // is only reachable via defer_account; without it an account always exists by the time the
    // Core constructor returns.
    AccountSeedAccess account_seed() {
        _require_account();
        auto acc = _account_seed.access();
        return AccountSeedAccess{acc};
    }
    // These are computed from the account_seed during construction:
    std::span<const std::byte, 33> session_id() {
        _require_account();
        return _session_id;
    }
    const std::string& session_id_hex() const {
        _require_account();
        return _session_id_hex;
    }
    const network::ed25519_pubkey& pubkey_ed25519() const {
        _require_account();
        return _pubkey_ed25519;
    }
    const network::x25519_pubkey& pubkey_x25519() const {
        _require_account();
        return _pubkey_x25519;
    }

    /// Returns the account seed as a mnemonic word list with checksum, stored in secure memory.
    ///
    /// If `force_24` is false (the default), returns 13 words when the upper 16 bytes of the
    /// seed are all zero (128-bit entropy), or 25 words otherwise.  If `force_24` is true,
    /// always returns 25 words.
    mnemonics::secure_mnemonic seed_mnemonic(
            const mnemonics::Mnemonics& lang, bool force_24 = false);
    mnemonics::secure_mnemonic seed_mnemonic(
            std::string_view lang_name = "English", bool force_24 = false);
};

}  // namespace session::core
