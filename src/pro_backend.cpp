#include <fmt/core.h>
#include <oxenc/hex.h>
#include <session/export.h>
#include <session/pro_backend.h>
#include <sodium/crypto_sign_ed25519.h>

#include <charconv>
#include <chrono>
#include <concepts>
#include <memory>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/sodium_array.hpp>
#include <session/types.hpp>
#include <session/util.hpp>

#include "json_parser.hpp"
#include "pro_message.hpp"

namespace {

using namespace session::detail;

// Fractional UNIX seconds (double) -> millisecond-precision system time, preserving the provider's
// sub-second precision (rounded to the nearest millisecond).
session::sys_ms sys_ms_from_seconds(double seconds) {
    return session::sys_ms(
            std::chrono::round<std::chrono::milliseconds>(std::chrono::duration<double>(seconds)));
}

// Millisecond-precision system time -> fractional UNIX seconds (double); the C API carries these
// two instants as double seconds (millisecond-precise, having passed through sys_ms).
double epoch_seconds_double(session::sys_ms t) {
    return std::chrono::duration<double>(t.time_since_epoch()).count();
}

};  // namespace

namespace session::pro_backend {

namespace {

    // Endpoint paths (single master storage). Both the C `SESSION_PRO_BACKEND_*_ENDPOINT` symbols
    // and the C++ `*_request()` return values point at these — the path is defined exactly once.
    constexpr char generate_proof_endpoint[] = "generate_pro_proof";
    constexpr char get_pro_status_endpoint[] = "get_pro_status";
    constexpr char get_payment_details_endpoint[] = "get_payment_details";
    constexpr char get_pro_revocations_endpoint[] = "get_pro_revocations";

    // Content type for the request payload (single master storage, shared with the C API's
    // session_pro_backend_request.content_type). The wire encoding is libsession's to change; the
    // content type travels alongside the payload so clients never hardcode a format.
    constexpr char application_json[] = "application/json";

    // Normalise an Ed25519 private key to libsodium's 64-byte form (seed(32) || pubkey(32)): a
    // 32-byte seed is expanded, a 64-byte key copied, anything else throws. The public key is then
    // available at bytes [32, 64) so callers never need a second derivation.
    cleared_uc64 normalize_privkey(std::span<const uint8_t> privkey, const char* name) {
        cleared_uc64 out;
        if (privkey.size() == crypto_sign_ed25519_SEEDBYTES) {
            array_uc32 pubkey;
            crypto_sign_ed25519_seed_keypair(pubkey.data(), out.data(), privkey.data());
        } else if (privkey.size() == crypto_sign_ed25519_SECRETKEYBYTES) {
            std::memcpy(out.data(), privkey.data(), crypto_sign_ed25519_SECRETKEYBYTES);
        } else {
            throw std::invalid_argument{fmt::format("Invalid {}: expected 32 or 64 bytes", name)};
        }
        return out;
    }

    // Public-key view (bytes [32, 64)) of a normalised 64-byte private key.
    std::span<const uint8_t, 32> pubkey_of(const cleared_uc64& priv64) {
        return std::span<const uint8_t, 32>(
                priv64.data() + crypto_sign_ed25519_SEEDBYTES, crypto_sign_ed25519_PUBLICKEYBYTES);
    }

}  // namespace

// C endpoint symbols: each points at the single master endpoint string defined above, so the C API
// and the C++ `ProRequest::endpoint` values are backed by one definition.
extern "C" {
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT =
        generate_proof_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_STATUS_ENDPOINT =
        get_pro_status_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PAYMENT_DETAILS_ENDPOINT =
        get_payment_details_endpoint;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT =
        get_pro_revocations_endpoint;

// Backend base URL + Ed25519 pubkey: C symbols pointing at the single C++ definitions above.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_URL = URL.data();
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY = PUBKEY.data();
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY_X25519 =
        PUBKEY_X25519.data();

// Payment-provider code strings: C symbols pointing at the single C++ definitions above.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY =
        PAYMENT_PROVIDER_GOOGLE_PLAY.data();
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE =
        PAYMENT_PROVIDER_APP_STORE.data();
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_STF =
        PAYMENT_PROVIDER_STF.data();
}

using namespace std::literals;

// Fixed per-provider URL sets; provider_urls() just maps a provider code to one of these. The
// values are `""sv` literals so clang-format keeps each URL on one line (it won't split a string
// literal).
constexpr ProviderURLs google_play_urls{
        .refund_platform_url = "https://support.google.com/googleplay/workflow/9813244?"sv,
        .refund_support_url = "https://getsession.org/refund-android"sv,
        .refund_status_url = "https://getsession.org/refund-android"sv,
        .update_subscription_url =
                "https://play.google.com/store/account/subscriptions?package=network.loki.messenger"sv,
        .cancel_subscription_url =
                "https://play.google.com/store/account/subscriptions?package=network.loki.messenger"sv,
};
constexpr ProviderURLs app_store_urls{
        .refund_platform_url = "https://support.apple.com/118223"sv,
        .refund_support_url = "https://support.apple.com/118223"sv,
        .refund_status_url = "https://support.apple.com/118224"sv,
        .update_subscription_url = "https://apps.apple.com/account/subscriptions"sv,
        .cancel_subscription_url =
                "https://account.apple.com/account/manage/section/subscriptions"sv,
};

const ProviderURLs* provider_urls(std::string_view provider_code) {
    if (provider_code == PAYMENT_PROVIDER_GOOGLE_PLAY)
        return &google_play_urls;
    if (provider_code == PAYMENT_PROVIDER_APP_STORE)
        return &app_store_urls;
    // STF and unknown providers have no applicable URLs
    return nullptr;
}

LIBSESSION_C_API session_pro_backend_provider_urls
session_pro_backend_get_provider_urls(const char* provider_code) {
    // Each present field is a static, null-terminated literal; an absent one is NULL. `found`
    // distinguishes an unknown provider ({} -> found == false) from a recognised provider that
    // simply has some/all URLs absent.
    auto c = [](const std::optional<std::string_view>& u) -> const char* {
        return u ? u->data() : nullptr;
    };
    if (auto u = provider_urls(provider_code))
        return {.found = true,
                .refund_platform_url = c(u->refund_platform_url),
                .refund_support_url = c(u->refund_support_url),
                .refund_status_url = c(u->refund_status_url),
                .update_subscription_url = c(u->update_subscription_url),
                .cancel_subscription_url = c(u->cancel_subscription_url)};
    return {};
}

std::span<const std::string_view> visible_platforms() {
    static const std::array<std::string_view, 2> platforms = {
            PAYMENT_PROVIDER_GOOGLE_PLAY, PAYMENT_PROVIDER_APP_STORE};
    return platforms;
}

std::optional<ProPlanPeriod> parse_plan_period(std::string_view code) {
    // pro-wire-protocol.md §1: closed grammar. "lifetime", or "<N><unit>" with N a
    // positive integer (no leading zeros) and unit one of s/d/w/m/y. Single-unit only.
    if (code == "lifetime")
        return ProPlanPeriod{0, ProPlanUnit::lifetime};

    if (code.size() < 2)
        return std::nullopt;
    ProPlanUnit unit;
    switch (code.back()) {
        case 's': unit = ProPlanUnit::second; break;
        case 'd': unit = ProPlanUnit::day; break;
        case 'w': unit = ProPlanUnit::week; break;
        case 'm': unit = ProPlanUnit::month; break;
        case 'y': unit = ProPlanUnit::year; break;
        default: return std::nullopt;
    }

    // N = [1-9][0-9]*: reject a leading zero (or sign) up front, then require from_chars to consume
    // every remaining digit into a positive int (this also rejects overflow).
    std::string_view digits = code.substr(0, code.size() - 1);
    if (digits.empty() || digits.front() < '1' || digits.front() > '9')
        return std::nullopt;
    int count = 0;
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), count);
    if (ec != std::errc{} || ptr != digits.data() + digits.size())
        return std::nullopt;
    return ProPlanPeriod{count, unit};
}

LIBSESSION_C_API const char* const* session_pro_backend_visible_platforms(size_t* count) {
    // Derived from the C++ list (single source); each slug's data() is a static, null-terminated
    // literal, so the pointer array is safe to hand out as static storage.
    static const std::vector<const char*> codes = [] {
        std::vector<const char*> v;
        for (auto slug : visible_platforms())
            v.push_back(slug.data());
        return v;
    }();
    if (count)
        *count = codes.size();
    return codes.data();
}

namespace {
    // libsession-side slug when the backend's reply can't be parsed at all (malformed envelope,
    // missing/unrecognized status). Distinct from any backend error_code slug.
    constexpr std::string_view invalid_response_code = "invalid_response";

    // Read the response envelope (spec §5) into `result`: string `status` -> ResponseStatus (a
    // CLOSED set -- an unrecognized value throws, never passed through) and, on non-ok,
    // `error_code`
    // + `error`. Returns the `result` object to read the payload from when status is "ok" (an empty
    // object otherwise; the caller returns early on `!result`). Throws parse_error on a malformed
    // envelope.
    nlohmann::json::object_t read_envelope(std::string_view json, ResponseBase& result) {
        nlohmann::json j = json_parse(json);
        auto status = json_require<std::string>(j, "status");
        if (status == "ok") {
            result.status = ResponseStatus::Ok;
            return json_require<nlohmann::json::object_t>(j, "result");
        }
        if (status == "fail" || status == "error") {
            result.status = status == "fail" ? ResponseStatus::Fail : ResponseStatus::Error;
            result.error_code = json_require<std::string>(j, "error_code");
            result.error = json_require<std::string>(j, "error");
            return {};
        }
        throw parse_error{fmt::format("Unrecognized response status: '{}'", status)};
    }

    // Fills the common proof payload (add-payment and generate-proof both reply with exactly a
    // proof) from the already-extracted `result` object.
    void fill_proof(const nlohmann::json::object_t& result_obj, GenerateProProofResponse& result) {
        // No `version` to read: the format is fixed by the endpoint we asked, and is bound into the
        // proof's signature by its domain prefix rather than carried as a field. A future format is
        // a new endpoint returning its own proof type, not a version bump on this response.
        result.proof.expiry_at = json_require<std::chrono::sys_seconds>(result_obj, "expiry_ts");
        json_require_hex(result_obj, "revocation_tag", result.proof.revocation_tag);
        json_require_hex(result_obj, "rotating_pkey", result.proof.rotating_pubkey);
        json_require_hex(result_obj, "sig", result.proof.sig);

        // Advisory and unsigned (pro-wire-protocol.md §2.2) -- never fed into signature
        // verification -- but required: a proof response without it can't refresh the cached access
        // expiry, which breaks renewal, so treat a missing value as a malformed response.
        result.account_expiry =
                json_require<std::chrono::sys_seconds>(result_obj, "account_expiry_ts");

        // The two values that qualify `account_expiry_ts`. Absent -> keep the {0}/{false} default:
        // the backend sends `0`/`false` whenever grace/renewal don't apply and omits them on a
        // backend that predates them, so a missing field means "not applicable", never "keep the
        // stale value". A present value must still be well-formed (a wrong type throws).
        if (result_obj.contains("account_grace_period_duration"))
            result.account_grace_period =
                    json_require<std::chrono::seconds>(result_obj, "account_grace_period_duration");
        if (result_obj.contains("account_auto_renewing"))
            result.account_auto_renewing = json_require<bool>(result_obj, "account_auto_renewing");
    }
}  // namespace

GenerateProProofResponse parse_pro_proof(std::string_view json) {
    GenerateProProofResponse result = {};
    auto result_obj = read_envelope(json, result);
    if (!result) {
        // On a subscription_expired failure the account's (now-past) true expiry rides top-level on
        // the envelope, alongside the same grace/renewal qualifiers as the success path
        // (pro-wire-protocol.md §2.2 / §5.1), so the client can refresh all three without a
        // separate get_pro_status. They must travel together: coverage ends at `account_expiry +
        // grace`, and an expiry has typically NOT changed on this failure (it is a
        // lapse/cancellation) while the grace and flag have -- refreshing only the expiry would
        // leave a stale grace claiming coverage the backend has stopped honouring. Read leniently,
        // absent -> {0}/{false} as on the success path (the envelope already parsed, so json_parse
        // here can't throw).
        if (result.error_code == "subscription_expired") {
            auto j = json_parse(json);
            if (auto expiry = json_maybe<std::chrono::sys_seconds>(j, "account_expiry_ts"))
                result.account_expiry = *expiry;
            if (j.contains("account_grace_period_duration"))
                result.account_grace_period =
                        json_require<std::chrono::seconds>(j, "account_grace_period_duration");
            if (j.contains("account_auto_renewing"))
                result.account_auto_renewing = json_require<bool>(j, "account_auto_renewing");
        }
        return result;
    }
    fill_proof(result_obj, result);
    return result;
}

namespace {

    // --- generate-proof (endpoint generate_pro_proof) ---

    std::vector<unsigned char> generate_proof_message(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 32> rotating_pubkey,
            std::chrono::sys_seconds unix_ts) {
        // Must match the generate-proof signed-request message in pro-wire-protocol.md §3.1,
        // built per §1.1.
        return session::pro::signed_message(
                session::GENERATE_PROOF_DOMAIN,
                master_pubkey,
                rotating_pubkey,
                epoch_seconds(unix_ts));
    }

    MasterRotatingSignatures generate_proof_sign(
            const cleared_uc64& master,
            const cleared_uc64& rotating,
            std::chrono::sys_seconds unix_ts) {
        auto msg = generate_proof_message(pubkey_of(master), pubkey_of(rotating), unix_ts);
        MasterRotatingSignatures result = {};
        crypto_sign_ed25519_detached(
                result.master_sig.data(), nullptr, msg.data(), msg.size(), master.data());
        crypto_sign_ed25519_detached(
                result.rotating_sig.data(), nullptr, msg.data(), msg.size(), rotating.data());
        return result;
    }

    std::string generate_proof_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 32> rotating_pubkey,
            std::chrono::sys_seconds unix_ts,
            std::span<const uint8_t, 64> master_sig,
            std::span<const uint8_t, 64> rotating_sig) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"rotating_pkey", oxenc::to_hex(rotating_pubkey)},
                {"ts", epoch_seconds(unix_ts)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"rotating_sig", oxenc::to_hex(rotating_sig)}}
                .dump();
    }

}  // namespace

ProRequest pro_proof_request(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        std::chrono::sys_seconds unix_ts) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto rotating = normalize_privkey(rotating_privkey, "rotating_privkey");
    auto sigs = generate_proof_sign(master, rotating, unix_ts);
    return {generate_proof_endpoint,
            application_json,
            generate_proof_body(
                    pubkey_of(master),
                    pubkey_of(rotating),
                    unix_ts,
                    sigs.master_sig,
                    sigs.rotating_sig)};
}

ProRequest revocations_request(std::int64_t ticket) {
    nlohmann::json j;
    j["ticket"] = ticket;
    return {get_pro_revocations_endpoint, application_json, j.dump()};
}

GetProRevocationsResponse parse_revocations(std::string_view json) {
    GetProRevocationsResponse result = {};
    auto result_obj = read_envelope(json, result);
    if (!result)
        return result;

    // Parse payload
    result.ticket = json_require<int64_t>(result_obj, "ticket");
    result.retry_in = json_require<std::chrono::seconds>(result_obj, "retry_in");
    result.retain_for = json_require<std::chrono::seconds>(result_obj, "retain_for");

    // Clamp values against non-sensical/catastrophic values: retry_in of very small would result in
    // excess retries, and an overly long retry (e.g. 10 years) would make the client not properly
    // refresh at all.  The retain_for clamp is deliberately larger because that is only a hint as
    // to when the record can be cleaned up.
    result.retry_in = std::clamp<std::chrono::seconds>(result.retry_in, 60s, 48h);
    result.retain_for = std::clamp<std::chrono::seconds>(result.retain_for, 24h, 365 * 24h);

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items");
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object())
            throw parse_error{fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1))};

        auto obj = it.get<nlohmann::json::object_t>();
        ProRevocationItem item = {};
        item.effective_at = json_require<std::chrono::sys_seconds>(obj, "effective_ts");
        json_require_hex(obj, "revocation_tag", item.revocation_tag);
        result.items.emplace_back(std::move(item));
    }

    return result;
}

namespace {

    // --- get-pro-status (endpoint get_pro_status) ---

    std::vector<unsigned char> pro_status_message(
            std::span<const uint8_t, 32> master_pubkey, std::chrono::sys_seconds unix_ts) {
        // Must match the get-pro-status signed-request message in pro-wire-protocol.md §3.2, built
        // per §1.1.
        return session::pro::signed_message(
                session::GET_PRO_STATUS_DOMAIN, master_pubkey, epoch_seconds(unix_ts));
    }

    array_uc64 pro_status_sign(const cleared_uc64& master, std::chrono::sys_seconds unix_ts) {
        auto msg = pro_status_message(pubkey_of(master), unix_ts);
        array_uc64 sig = {};
        crypto_sign_ed25519_detached(sig.data(), nullptr, msg.data(), msg.size(), master.data());
        return sig;
    }

    std::string pro_status_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 64> master_sig,
            std::chrono::sys_seconds unix_ts) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"ts", epoch_seconds(unix_ts)}}
                .dump();
    }

    // --- get-payment-details (endpoint get_payment_details) ---

    std::vector<unsigned char> payment_details_message(
            std::span<const uint8_t, 32> master_pubkey,
            std::chrono::sys_seconds unix_ts,
            uint32_t limit,
            std::string_view before) {
        // Must match the get-payment-details signed-request message in pro-wire-protocol.md §3.3,
        // built per §1.1. `before` is the opaque pagination cursor (§5.3), empty for the newest
        // page.
        return session::pro::signed_message(
                session::GET_PAYMENT_DETAILS_DOMAIN,
                master_pubkey,
                epoch_seconds(unix_ts),
                limit,
                before);
    }

    array_uc64 payment_details_sign(
            const cleared_uc64& master,
            std::chrono::sys_seconds unix_ts,
            uint32_t limit,
            std::string_view before) {
        auto msg = payment_details_message(pubkey_of(master), unix_ts, limit, before);
        array_uc64 sig = {};
        crypto_sign_ed25519_detached(sig.data(), nullptr, msg.data(), msg.size(), master.data());
        return sig;
    }

    std::string payment_details_body(
            std::span<const uint8_t, 32> master_pubkey,
            std::span<const uint8_t, 64> master_sig,
            std::chrono::sys_seconds unix_ts,
            uint32_t limit,
            std::string_view before) {
        return nlohmann::json{
                {"master_pkey", oxenc::to_hex(master_pubkey)},
                {"master_sig", oxenc::to_hex(master_sig)},
                {"ts", epoch_seconds(unix_ts)},
                {"limit", limit},
                {"before", before}}
                .dump();
    }

    // Parse one payment item object (shared by get-pro-status's `latest_payment` and
    // get-payment-details's `items`). Throws parse_error on any malformed field.
    ProPaymentItem parse_payment_item(const nlohmann::json::object_t& obj) {
        auto status = json_require<std::string>(obj, "status");
        auto plan_code = json_require<std::string>(obj, "plan");
        auto plan = parse_plan_period(plan_code);
        if (!plan)
            throw parse_error{
                    fmt::format("'plan' is not a recognized billing-period code: '{}'", plan_code)};
        auto payment_provider = json_require<std::string>(obj, "payment_provider");
        auto payment_id = json_require<std::string>(obj, "payment_id");
        auto auto_renewing = json_require<bool>(obj, "auto_renewing");
        // purchased_ts and revoked_ts are upstream-provider event instants: floats on the wire
        // carrying sub-second precision (kept as millisecond-precision sys_ms). All other
        // timestamps are whole-second integers.
        auto purchased_ts = json_require<double>(obj, "purchased_ts");
        auto expiry_at = json_require<std::chrono::sys_seconds>(obj, "expiry_ts");
        auto grace_period_duration =
                json_require<std::chrono::seconds>(obj, "grace_period_duration");
        auto platform_refund_expiry_at =
                json_require<std::chrono::sys_seconds>(obj, "platform_refund_expiry_ts");
        auto revoked_ts = json_require<double>(obj, "revoked_ts");

        ProPaymentItem item = {};
        item.status = std::move(status);
        item.plan = *plan;
        item.payment_provider = std::move(payment_provider);
        item.payment_id = std::move(payment_id);
        item.auto_renewing = auto_renewing;
        item.purchased_at = sys_ms_from_seconds(purchased_ts);
        item.expiry_at = expiry_at;
        item.grace_period_duration = grace_period_duration;
        item.platform_refund_expiry_at = platform_refund_expiry_at;
        item.revoked_at = sys_ms_from_seconds(revoked_ts);
        return item;
    }

}  // namespace

ProRequest pro_status_request(
        std::span<const uint8_t> master_privkey, std::chrono::sys_seconds unix_ts) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto sig = pro_status_sign(master, unix_ts);
    return {get_pro_status_endpoint,
            application_json,
            pro_status_body(pubkey_of(master), sig, unix_ts)};
}

ProRequest payment_details_request(
        std::span<const uint8_t> master_privkey,
        std::chrono::sys_seconds unix_ts,
        uint32_t limit,
        std::string_view before) {
    auto master = normalize_privkey(master_privkey, "master_privkey");
    auto sig = payment_details_sign(master, unix_ts, limit, before);
    return {get_payment_details_endpoint,
            application_json,
            payment_details_body(pubkey_of(master), sig, unix_ts, limit, before)};
}

ProStatusResponse parse_pro_status(std::string_view json) {
    ProStatusResponse result = {};
    auto result_obj = read_envelope(json, result);
    if (!result)
        return result;

    // Parse payload. The account Pro status is an opaque string code ("never"/"active"/"expired");
    // an unknown value passes through unchanged (§1: enums are codes) rather than failing the
    // parse. (Wire key `user_status`, disambiguated from the envelope `status` -- spec §5.2.)
    result.user_status = json_require<std::string>(result_obj, "user_status");
    result.auto_renewing = json_require<bool>(result_obj, "auto_renewing");
    result.expiry_at = json_require<std::chrono::sys_seconds>(result_obj, "expiry_ts");
    result.grace_period_duration =
            json_require<std::chrono::seconds>(result_obj, "grace_period_duration");

    // `latest_payment` is a single payment item, or null when the account has no payments.
    if (auto it = result_obj.find("latest_payment"); it == result_obj.end())
        throw parse_error_missing{"latest_payment"};
    else if (it->second.is_null()) {
        // No payments: latest_payment stays std::nullopt.
    } else if (it->second.is_object())
        result.latest_payment = parse_payment_item(it->second.get<nlohmann::json::object_t>());
    else
        throw parse_error_type{"latest_payment", "an object or null", it->second.dump(1)};

    return result;
}

PaymentDetailsResponse parse_payment_details(std::string_view json) {
    PaymentDetailsResponse result = {};
    auto result_obj = read_envelope(json, result);
    if (!result)
        return result;

    result.payments_total = json_require<uint32_t>(result_obj, "payments_total");

    auto array = json_require<nlohmann::json::array_t>(result_obj, "items");
    result.items.reserve(array.size());
    for (size_t index = 0; index < array.size(); index++) {
        const auto& it = array[index];
        if (!it.is_object())
            throw parse_error{fmt::format(
                    "Aborting parse, 'items[{}]' was not an object: {}", index, it.dump(1))};
        result.items.emplace_back(parse_payment_item(it.get<nlohmann::json::object_t>()));
    }

    // `next_cursor` is the opaque keyset cursor (§5.3), or null at end-of-data.
    if (auto it = result_obj.find("next_cursor"); it == result_obj.end())
        throw parse_error_missing{"next_cursor"};
    else if (it->second.is_null()) {
        // End of data: next_cursor stays std::nullopt.
    } else if (it->second.is_string())
        result.next_cursor = it->second.get<std::string>();
    else
        throw parse_error_type{"next_cursor", "a string or null", it->second.dump(1)};

    return result;
}

}  // namespace session::pro_backend

using namespace session::pro_backend;

// error / error_code strings libsession synthesizes when it cannot parse or build the C response.
static constexpr const char* C_PARSE_ERROR_OUT_OF_MEMORY = "Ran out-of-memory creating C response";
static constexpr const char* C_PARSE_ERROR_INVALID_ARGS = "One or more C arguments were NULL";
static constexpr const char* C_INVALID_RESPONSE_CODE = "invalid_response";

// Map the C++ ResponseStatus to the C enum.
static SESSION_PRO_BACKEND_RESPONSE_STATUS c_response_status(ResponseStatus status) {
    switch (status) {
        case ResponseStatus::Ok: return SESSION_PRO_BACKEND_RESPONSE_STATUS_OK;
        case ResponseStatus::Fail: return SESSION_PRO_BACKEND_RESPONSE_STATUS_FAIL;
        case ResponseStatus::Error: break;
    }
    return SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
}

// Fill a C response header from a C++ ResponseBase. error_code/error point into `cpp`
// (NUL-terminated via c_str(), NULL when absent); `cpp` is owned by the response's
// header.internal_.
static void fill_c_header(session_pro_backend_response_header& header, const ResponseBase& cpp) {
    header.status = c_response_status(cpp.status);
    header.error_code = cpp.error_code ? cpp.error_code->c_str() : nullptr;
    header.error = cpp.error ? cpp.error->c_str() : nullptr;
}

// Translate a parse_error (or any std::exception) caught at the C boundary into an
// "invalid_response" protocol error on the C header. Heap-owns a response of concrete type `Owned`
// (deriving from ResponseBase) to carry the diagnostic `what` so it outlives the call and is freed
// by the response's *_free. Falls back to static strings if even that holder can't be allocated.
template <std::derived_from<ResponseBase> Owned>
static void set_c_protocol_error(session_pro_backend_response_header& header, const char* what) {
    try {
        auto owned = std::make_unique<Owned>();
        owned->status = ResponseStatus::Error;
        owned->error_code = std::string(invalid_response_code);
        owned->error = what;
        fill_c_header(header, *owned);
        header.internal_ = owned.release();
    } catch (...) {
        header.internal_ = nullptr;
        header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        header.error_code = C_INVALID_RESPONSE_CODE;
        header.error = C_PARSE_ERROR_OUT_OF_MEMORY;
    }
}

// Project a parsed C++ item to its C view. The string members are pointers into `src` (valid while
// the owning response lives) -- kept file-local rather than a public conversion operator, and
// taking a non-const lvalue ref so a temporary (whose aliased strings would immediately dangle)
// can't bind.
static session_pro_backend_pro_revocation_item to_c(ProRevocationItem& src) {
    return {
            .revocation_tag = src.revocation_tag.data(),
            .effective_ts = session::epoch_seconds(src.effective_at),
    };
}

static session_pro_backend_pro_payment_item to_c(ProPaymentItem& src) {
    return {
            .status = src.status.c_str(),
            .plan_count = src.plan.count,
            .plan_unit = static_cast<SESSION_PRO_BACKEND_PLAN_UNIT>(src.plan.unit),
            .payment_provider = src.payment_provider.c_str(),
            .auto_renewing = src.auto_renewing,
            .purchased_ts = epoch_seconds_double(src.purchased_at),
            .expiry_ts = session::epoch_seconds(src.expiry_at),
            .grace_period_duration = src.grace_period_duration.count(),
            .platform_refund_expiry_ts = session::epoch_seconds(src.platform_refund_expiry_at),
            .revoked_ts = epoch_seconds_double(src.revoked_at),
            .payment_id = src.payment_id.c_str(),
    };
}

// Owns the parsed C++ response object that a C response's fields point into, plus the C item-view
// array. `header.internal_` points here; the response's *_free deletes it. (Item-less responses own
// the bare C++ object directly.)
//
// Each takes an explicit base-slice constructor rather than relying on aggregate initialization:
// the *_parse functions build these with std::make_unique from a parsed base response, and
// make_unique initializes with parentheses, which only aggregate-initializes under P0960R3
// (C++20). GCC implements that, but the Apple Clang used by the macOS CI runners does not, so it
// looks for a constructor and finds none. The defaulted default constructor is kept because
// set_c_protocol_error<Owned> default-constructs these to carry a diagnostic.
struct GetProRevocationsCResponse : GetProRevocationsResponse {
    GetProRevocationsCResponse() = default;
    explicit GetProRevocationsCResponse(GetProRevocationsResponse&& base) :
            GetProRevocationsResponse{std::move(base)} {}

    std::vector<session_pro_backend_pro_revocation_item> item_views;
};
struct GetPaymentDetailsCResponse : PaymentDetailsResponse {
    GetPaymentDetailsCResponse() = default;
    explicit GetPaymentDetailsCResponse(PaymentDetailsResponse&& base) :
            PaymentDetailsResponse{std::move(base)} {}

    std::vector<session_pro_backend_pro_payment_item> item_views;
};

// Free any C response: delete the owned object (of concrete type `Owned`, as stored by the matching
// *_parse) behind header.internal_, then zero the struct. `Owned` is a proof response or a
// *CResponse holder -- all deriving from ResponseBase.
template <std::derived_from<ResponseBase> Owned, typename Response>
static void c_free_response(Response* response) {
    if (response) {
        delete static_cast<Owned*>(response->header.internal_);
        *response = {};
    }
}

// Wrap a freshly-built C++ ProRequest as an owning C session_pro_backend_request: heap-own the
// ProRequest and point endpoint/content_type/data into it (zero copy). Released by
// session_pro_backend_request_free.
static session_pro_backend_request c_own_request(ProRequest&& req) {
    auto owned = std::make_unique<ProRequest>(std::move(req));
    session_pro_backend_request result = {};
    result.endpoint = owned->endpoint.data();
    result.content_type = owned->content_type.data();
    result.data = span_u8{reinterpret_cast<uint8_t*>(owned->data.data()), owned->data.size()};
    result.success = true;
    result.internal_ = owned.release();
    return result;
}

// Fill a session_pro_backend_request's error buffer from a caught exception.
static void c_request_error(session_pro_backend_request& result, const std::exception& e) {
    const std::string& error = e.what();
    result.error_count = snprintf_clamped(
            result.error,
            sizeof(result.error),
            "%.*s",
            static_cast<int>(error.size()),
            error.data());
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_generate_pro_proof_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(pro_proof_request(
                {master_privkey, master_privkey_len},
                {rotating_privkey, rotating_privkey_len},
                session::as_sys_seconds(ts)));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request
session_pro_backend_get_pro_revocations_request_build(int64_t ticket) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(revocations_request(ticket));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_get_pro_status_request_build(
        const uint8_t* master_privkey, size_t master_privkey_len, int64_t ts) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(pro_status_request(
                {master_privkey, master_privkey_len}, session::as_sys_seconds(ts)));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_request session_pro_backend_get_payment_details_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        uint32_t limit,
        const char* before) {
    session_pro_backend_request result = {};
    try {
        result = c_own_request(payment_details_request(
                {master_privkey, master_privkey_len},
                session::as_sys_seconds(ts),
                limit,
                before ? std::string_view{before} : std::string_view{}));
    } catch (const std::exception& e) {
        c_request_error(result, e);
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_pro_proof_response
session_pro_backend_pro_proof_response_parse(const char* json, size_t json_len) {

    session_pro_backend_pro_proof_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    try {
        auto owned = std::make_unique<GenerateProProofResponse>(parse_pro_proof({json, json_len}));
        fill_c_header(result.header, *owned);

        // Success and error responses fold into one path -- different fields populated.
        const auto& p = owned->proof;
        result.proof.expiry_ts = session::epoch_seconds(p.expiry_at);
        std::memcpy(
                result.proof.revocation_tag.data, p.revocation_tag.data(), p.revocation_tag.size());
        std::memcpy(
                result.proof.rotating_pubkey.data,
                p.rotating_pubkey.data(),
                p.rotating_pubkey.size());
        std::memcpy(result.proof.sig.data, p.sig.data(), p.sig.size());
        result.account_expiry_ts =
                owned->account_expiry ? session::epoch_seconds(*owned->account_expiry) : 0;
        result.account_grace_period_duration = owned->account_grace_period.count();
        result.account_auto_renewing = owned->account_auto_renewing;
        // All C fields aliased into *owned; hand ownership to the response (freed by *_free).
        result.header.internal_ = owned.release();
    } catch (const std::exception& e) {
        result = {};
        set_c_protocol_error<GenerateProProofResponse>(result.header, e.what());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_revocations_response
session_pro_backend_get_pro_revocations_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_revocations_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    try {
        auto owned =
                std::make_unique<GetProRevocationsCResponse>(parse_revocations({json, json_len}));
        fill_c_header(result.header, *owned);
        result.ticket = owned->ticket;
        result.retry_in = owned->retry_in.count();
        result.retain_for = owned->retain_for.count();

        owned->item_views.reserve(owned->items.size());
        for (auto& src : owned->items)
            owned->item_views.push_back(to_c(src));
        result.items = owned->item_views.data();
        result.items_count = owned->item_views.size();
        result.header.internal_ = owned.release();
    } catch (const std::exception& e) {
        result = {};
        set_c_protocol_error<GetProRevocationsCResponse>(result.header, e.what());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_pro_status_response
session_pro_backend_get_pro_status_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_pro_status_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    try {
        using session::epoch_seconds;
        auto owned = std::make_unique<ProStatusResponse>(parse_pro_status({json, json_len}));
        fill_c_header(result.header, *owned);

        result.status = owned->user_status.c_str();
        result.auto_renewing = owned->auto_renewing;
        result.expiry_ts = epoch_seconds(owned->expiry_at);
        result.grace_period_duration = owned->grace_period_duration.count();
        result.has_latest_payment = owned->latest_payment.has_value();
        if (owned->latest_payment)
            result.latest_payment = to_c(*owned->latest_payment);
        result.header.internal_ = owned.release();
    } catch (const std::exception& e) {
        result = {};
        set_c_protocol_error<ProStatusResponse>(result.header, e.what());
    }
    return result;
}

LIBSESSION_C_API session_pro_backend_get_payment_details_response
session_pro_backend_get_payment_details_response_parse(const char* json, size_t json_len) {
    session_pro_backend_get_payment_details_response result = {};
    if (!json) {
        result.header.status = SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR;
        result.header.error_code = C_INVALID_RESPONSE_CODE;
        result.header.error = C_PARSE_ERROR_INVALID_ARGS;
        return result;
    }

    try {
        auto owned = std::make_unique<GetPaymentDetailsCResponse>(
                parse_payment_details({json, json_len}));
        fill_c_header(result.header, *owned);

        result.payments_total = owned->payments_total;
        result.next_cursor = owned->next_cursor ? owned->next_cursor->c_str() : nullptr;

        owned->item_views.reserve(owned->items.size());
        for (auto& src : owned->items)
            owned->item_views.push_back(to_c(src));
        result.items = owned->item_views.data();
        result.items_count = owned->item_views.size();
        result.header.internal_ = owned.release();
    } catch (const std::exception& e) {
        result = {};
        set_c_protocol_error<GetPaymentDetailsCResponse>(result.header, e.what());
    }
    return result;
}

LIBSESSION_C_API void session_pro_backend_request_free(session_pro_backend_request* request) {
    if (request) {
        if (request->internal_)
            delete static_cast<ProRequest*>(request->internal_);
        *request = {};
    }
}

LIBSESSION_C_API void session_pro_backend_pro_proof_response_free(
        session_pro_backend_pro_proof_response* response) {
    c_free_response<GenerateProProofResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_get_pro_revocations_response_free(
        session_pro_backend_get_pro_revocations_response* response) {
    c_free_response<GetProRevocationsCResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_get_pro_status_response_free(
        session_pro_backend_get_pro_status_response* response) {
    c_free_response<ProStatusResponse>(response);
}

LIBSESSION_C_API void session_pro_backend_get_payment_details_response_free(
        session_pro_backend_get_payment_details_response* response) {
    c_free_response<GetPaymentDetailsCResponse>(response);
}
