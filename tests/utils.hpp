#pragma once

#include <fmt/format.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using namespace oxenc::literals;
using namespace oxen::log::literals;

namespace session {

/// RAII class that resets the log level for the given category while the object is alive, then
/// resets it to what it was at construction when the object is destroyed.
struct log_level_override {
    oxen::log::Level previous;
    std::string category;

    log_level_override(oxen::log::Level l, std::string category) :
            previous{oxen::log::get_level(category)}, category{category} {
        oxen::log::set_level(category, l);
    }
    ~log_level_override() { oxen::log::set_level(category, previous); }
};

/// Same as above, but only raises the log level to a more serious cutoff (leaving it alone if
/// already higher).
struct log_level_raiser : log_level_override {
    log_level_raiser(oxen::log::Level l, std::string category) :
            log_level_override{std::max(l, oxen::log::get_level(category)), category} {}
};
/// Same as above, but only lowers the log level to a more frivolous cutoff (leaving it alone if
/// already lower).
struct log_level_lowerer : log_level_override {
    log_level_lowerer(oxen::log::Level l, std::string category) :
            log_level_override{std::min(l, oxen::log::get_level(category)), category} {}
};

class CallTracker {
  protected:
    std::unordered_map<std::string, int> call_counts_;
    std::mutex call_counts_mutex_;
    std::condition_variable call_cv_;
    std::vector<std::string> calls_to_ignore_;

  public:
    virtual ~CallTracker() = default;

    void func_called(const std::string& name) {
        bool notify = false;
        {
            std::lock_guard<std::mutex> lock(call_counts_mutex_);
            ++call_counts_[name];
            notify = true;
        }

        if (notify)
            call_cv_.notify_all();
    }

    std::vector<std::string> calls_to_ignore() { return calls_to_ignore_; }

    bool check_should_ignore_and_log_call(const std::string& name) {
        func_called(name);
        return std::find(calls_to_ignore_.begin(), calls_to_ignore_.end(), name) !=
               calls_to_ignore_.end();
    }

    template <typename... Strings>
    void ignore_calls_to(Strings&&... args) {
        (calls_to_ignore_.emplace_back(std::forward<Strings>(args)), ...);
    }

    void reset_calls() {
        std::lock_guard<std::mutex> lock(call_counts_mutex_);
        call_counts_.clear();
        calls_to_ignore_.clear();
    }

    int get_call_count(const std::string& name) {
        std::lock_guard<std::mutex> lock(call_counts_mutex_);
        auto it = call_counts_.find(name);
        return (it != call_counts_.end()) ? it->second : 0;
    }

    bool called(const std::string& name, int times = 1) { return (get_call_count(name) >= times); }

    [[nodiscard]] bool called(
            const std::string& name, std::chrono::milliseconds timeout, int times = 1) {
        if (times <= 0)
            times = 1;

        std::unique_lock<std::mutex> lock(call_counts_mutex_);
        auto predicate = [&]() {
            auto it = call_counts_.find(name);
            return (it != call_counts_.end() && it->second >= times);
        };
        return call_cv_.wait_for(lock, timeout, predicate);
    }

    bool did_not_call(const std::string& name) {
        std::lock_guard<std::mutex> lock(call_counts_mutex_);
        return !call_counts_.contains(name);
    }

    [[nodiscard]] bool did_not_call(const std::string& name, std::chrono::milliseconds duration) {
        std::unique_lock<std::mutex> lock(call_counts_mutex_);
        auto predicate = [&]() { return call_counts_.contains(name); };

        if (predicate())
            return false;  // Already called

        bool was_called_during_wait = call_cv_.wait_for(lock, duration, predicate);
        return !was_called_during_wait;
    }
};

}  // namespace session

inline std::vector<unsigned char> operator""_bytes(const char* x, size_t n) {
    auto begin = reinterpret_cast<const unsigned char*>(x);
    return {begin, begin + n};
}
inline std::vector<unsigned char> operator""_hexbytes(const char* x, size_t n) {
    std::vector<unsigned char> bytes;
    oxenc::from_hex(x, x + n, std::back_inserter(bytes));
    return bytes;
}

inline std::string to_hex(std::vector<unsigned char> bytes) {
    std::string hex;
    oxenc::to_hex(bytes.begin(), bytes.end(), std::back_inserter(hex));
    return hex;
}

inline constexpr auto operator""_kiB(unsigned long long kiB) {
    return kiB * 1024;
}

// Returns the current timestamp in milliseconds
inline int64_t get_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

// Returns the current timestamp in seconds
inline int64_t get_timestamp_s() {
    return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    ;
}

// Returns the current timestamp in microseconds
inline int64_t get_timestamp_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

inline std::string printable(std::span<const unsigned char> x) {
    std::string p;
    for (auto c : x) {
        if (c >= 0x20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}
inline std::string printable(std::string_view x) {
    return printable(session::to_span(x));
}
template <typename... T>
    requires(sizeof...(T) > 0)
inline std::string printable(fmt::format_string<T...> format, T&&... args) {
    return printable(session::to_span(fmt::format(format, std::forward<T>(args)...)));
}
std::string printable(const unsigned char* x) = delete;
inline std::string printable(const unsigned char* x, size_t n) {
    return printable({x, n});
}

template <typename Container>
std::set<typename Container::value_type> as_set(const Container& c) {
    return {c.begin(), c.end()};
}

template <typename... T>
std::set<std::common_type_t<T...>> make_set(T&&... args) {
    return {std::forward<T>(args)...};
}

struct TestKeys {
    session::array_uc32 seed0;
    session::array_uc64 ed_sk0;
    session::array_uc32 ed_pk0;
    session::array_uc32 curve_pk0;
    session::array_uc33 session_pk0;

    session::array_uc32 seed1;
    session::array_uc64 ed_sk1;
    session::array_uc32 ed_pk1;
    session::array_uc32 curve_pk1;
    session::array_uc33 session_pk1;
};

static inline TestKeys get_deterministic_test_keys() {
    TestKeys result = {};

    // clang-format off
    // Key 0
    {
        // Seed
        auto seed0 = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
        std::memcpy(result.seed0.data(), seed0.data(), seed0.size());

        // Ed25519
        crypto_sign_ed25519_seed_keypair(result.ed_pk0.data(), result.ed_sk0.data(), result.seed0.data());

        // X25519
        bool converted = crypto_sign_ed25519_pk_to_curve25519(result.curve_pk0.data(), result.ed_pk0.data()) == 0;
        assert(converted);

        // Session PK
        result.session_pk0[0] = 0x05;
        std::memcpy(result.session_pk0.data() + 1, result.curve_pk0.data(), result.curve_pk0.size());
    }

    // Key 1
    {
        // Seed
        auto seed1 = "00112233445566778899aabbccddeeff00000000000000000000000000000000"_hexbytes;
        std::memcpy(result.seed1.data(), seed1.data(), seed1.size());

        // Ed25519
        crypto_sign_ed25519_seed_keypair(result.ed_pk1.data(), result.ed_sk1.data(), result.seed1.data());

        // X25519
        bool converted = crypto_sign_ed25519_pk_to_curve25519(result.curve_pk1.data(), result.ed_pk1.data()) == 0;
        assert(converted);

        // Session PK
        result.session_pk1[0] = 0x05;
        std::memcpy(result.session_pk1.data() + 1, result.curve_pk1.data(), result.curve_pk1.size());
    }

    assert(oxenc::to_hex(result.ed_sk0.begin(), result.ed_sk0.data() + crypto_sign_ed25519_SEEDBYTES) == oxenc::to_hex(result.seed0));
    assert(oxenc::to_hex(result.ed_pk0)      ==   "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    assert(oxenc::to_hex(result.curve_pk0)   ==   "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    assert(oxenc::to_hex(result.session_pk0) == "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");

    assert(oxenc::to_hex(result.ed_sk1.begin(), result.ed_sk1.data() + crypto_sign_ed25519_SEEDBYTES) == oxenc::to_hex(result.seed1));
    assert(oxenc::to_hex(result.ed_pk1)      ==   "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
    assert(oxenc::to_hex(result.curve_pk1)   ==   "aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    assert(oxenc::to_hex(result.session_pk1) == "05aa654f00fc39fc69fd0db829410ca38177d7732a8d2f0934ab3872ac56d5aa74");
    // clang-format on
    return result;
}

struct scope_exit {
    explicit scope_exit(std::function<void()> func) : cleanup(func) {}
    std::function<void()> cleanup;
    ~scope_exit() {
        if (cleanup)
            cleanup();
    }
};
