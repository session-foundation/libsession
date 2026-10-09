#pragma once

#include <oxenc/hex.h>
#include <session/pro_backend.h>

#include <chrono>
#include <optional>
#include <session/parse_error.hpp>
#include <session/session_protocol.hpp>
#include <session/types.hpp>
#include <span>
#include <stdexcept>
#include <string>

/// Helper functions to construct payloads to communicate with the Session Pro Backend. The data
/// structures here are largely bindings to the endpoints exposed on the Session Pro Backend; the
/// wire format they produce and parse is byte-pinned in pro-wire-protocol.md (the authoritative
/// spec).
///
/// The high level summary of the functionality in this file. Clients can:
///
/// 1. Obtain a Session Pro proof with `pro_proof_request(...)` and submit its
///    `{endpoint, content_type, data}` to the backend, which authorises the specified rotating
///    Ed25519 key. Redemption is implicit -- there is no client-submitted "add payment" step: the
///    store notifies the backend of a purchase out-of-band and any master-signed request binds the
///    account's unbound payments before answering (pro-wire-protocol.md §3). After a purchase the
///    client just requests a proof and, until the store notification has reached the backend, gets
///    a not-yet-entitled answer and retries.
///
///    Parse the server's reply with `parse_pro_proof(...)`. Clients should validate the response
///    and update their `UserProfile` by constructing a `ProConfig` with the `proof` from the
///    response and filling in the relevant rotating private key that the proof was authorised for.
///
/// 2. Attach the `ProProof` constructed from (1) into their messages. Libsession has helper
///    functions to embed the proof into their messages via the helper functions in the Session
///    Protocol header file. This is done by assigning the `ProProof` into the
///    `Content.proMessage.proof` protobuf structure. Additionally the caller will use
///    `pro_features_for_message` to determine the correct flags to assign the `features` to
///    `Content.proMessage.flags` in the protobuf structure.
///
///    Lastly the high-level libsession encoding functions accept the rotating private key to which
///    the protobuf encoded plaintext content will be signed and the payload augmented as necessary
///    to enable pro features for that message.
///
/// 3. Periodically poll the global revocation list which overrides the validity of current
///    circulating proofs. This is done by building the request via `revocations_request(...)` and
///    sending it to the backend.
///
///    Parse the reply with `parse_revocations(...)`, which contains the list that clients should
///    cache. Any incoming messages with a Pro proof that is in the list of revoked proofs will not
///    be entitled to Pro features.
///
/// 4. Query a user's Session Pro entitlement status for their Master Ed25519 key by building a
///    `pro_status_request(...)` query (the hot "am I Pro?" path) and submitting it. Parse the reply
///    with `parse_pro_status(...)`, which yields the account status plus its single latest payment.
///
///    For the full payment history (e.g. a receipts view), page through it with
///    `payment_details_request(...)` / `parse_payment_details(...)` using the opaque keyset cursor.
///
/// See the unit tests for examples of using the APIs mentioned.

namespace session::pro_backend {

using namespace oxenc::literals;

/// The Session Pro Backend's Ed25519 public key: verify that a proof was issued by the backend by
/// checking its signature against this key (see ProProof::verify_signature). This is the current
/// backend signing key (test deployment, expected to carry through to production).
constexpr auto PUBKEY = "479ffca8bcec7b4a0f0f7afe48b8a6d15635a8c7ff15ad16add05752c19414d4"_hex_u;
static_assert(PUBKEY.size() == 32);

/// The X25519 form of `PUBKEY` (the same key converted via crypto_sign_ed25519_pk_to_curve25519),
/// provided as a constant for clients that need the X25519 pubkey (e.g. to establish an encrypted
/// channel to the backend) without doing the conversion themselves. A unit test asserts these bytes
/// match the runtime conversion of `PUBKEY`, so the two cannot drift.
constexpr auto PUBKEY_X25519 =
        "ce5a75f64b6c43db6c1374d362c3ea9d85951c4f42a3d04cf94f87822d4f803b"_hex_u;
static_assert(PUBKEY_X25519.size() == 32);

/// The Session Pro Backend's production base URL: POST a request body to `<URL>/<endpoint>` (see
/// the SESSION_PRO_BACKEND_*_ENDPOINT paths). This is the canonical production value; a client may
/// point at a different dev/test server if it chooses.
constexpr std::string_view URL = "https://pro.session.codes";

/// Canonical payment-provider code strings — the `payment_provider` value the backend reports on a
/// payment item (§5.2) and the slug clients key their store/display logic on. Reference these
/// rather than hardcoding the slug so client code cannot drift from what libsession parses. The C
/// `SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*` symbols point at these. An unknown code is still
/// valid on the wire and passes through as an opaque string.
constexpr std::string_view PAYMENT_PROVIDER_GOOGLE_PLAY = "google_play";
constexpr std::string_view PAYMENT_PROVIDER_APP_STORE = "app_store";
// STF = the Session Technology Foundation's out-of-band grant (not a purchasable store).
constexpr std::string_view PAYMENT_PROVIDER_STF = "stf";

/// Response outcome category (the wire `status`, spec §5). CLOSED/exhaustive by design: the backend
/// will never add a fourth value, so libsession treats any unrecognized wire status as a protocol
/// error (fail-closed) rather than passing it through. New categories/detail arrive via
/// `error_code`, which IS open/extensible.
enum class ResponseStatus {
    Ok,     ///< Success; the response's payload fields are populated.
    Fail,   ///< Request rejected on client input / a precondition; retrying the identical request
            ///< won't help (except the `stale_request` error_code). See `error_code`.
    Error,  ///< Backend fault; the client did nothing wrong and the same request may succeed later.
};

struct ResponseBase {
    /// Outcome category; `success()` is the usual check. See ResponseStatus.
    ResponseStatus status = ResponseStatus::Ok;

    /// On non-Ok, a stable machine-readable slug identifying the outcome (spec §5.1), e.g.
    /// "not_subscribed", "subscription_expired", "stale_request". std::nullopt on success. Opaque
    /// and forward-compatible: map known slugs to localized text; for an unrecognized one fall back
    /// to `error` / the `status` category. (libsession synthesizes "invalid_response" if it cannot
    /// parse the backend's reply at all.)
    std::optional<std::string> error_code;

    /// On non-Ok, an English diagnostic string. NOT user-facing text (that comes from mapping
    /// `error_code` to a localized string); show it only when the slug is unrecognized, and it is
    /// always safe to log. std::nullopt on success.
    std::optional<std::string> error;

    /// Contextually convertible to bool: `if (response) { ... }` is true iff the request succeeded
    /// (status == Ok). Explicit, so it can't silently leak into arithmetic or comparisons.
    explicit operator bool() const { return status == ResponseStatus::Ok; }
};

struct MasterRotatingSignatures {
    array_uc64 master_sig;
    array_uc64 rotating_sig;
};

/// Per-provider support/management URLs (from provider_urls()). These are identical for every user
/// (not translation data), so libsession owns them as the single source of truth rather than each
/// client duplicating them; the human-readable provider/store *names* are translation data and
/// remain the client's job. Each field is std::nullopt when that provider has no such URL --
/// clients test the optional rather than an empty-string sentinel. Present views point at static,
/// null-terminated string literals.
struct ProviderURLs {
    std::optional<std::string_view> refund_platform_url;  ///< Native store refund flow
    std::optional<std::string_view> refund_support_url;   ///< Session page for requesting a refund
    std::optional<std::string_view> refund_status_url;    ///< Where a user checks refund status
    std::optional<std::string_view> update_subscription_url;  ///< Manage/update the subscription
    std::optional<std::string_view> cancel_subscription_url;  ///< Cancel the subscription
};

/// Look up the support/management URLs for a provider code (see
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_*). Returns a pointer to a static per-provider
/// constant, or nullptr for a provider with no applicable URLs at all (an unknown code, or e.g.
/// STF); within a returned set each field is present or std::nullopt per that provider.
const ProviderURLs* provider_urls(std::string_view provider_code);

/// The user-visible purchasable platforms, as provider-code slugs (a subset of the
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_* values — currently "google_play" and "app_store").
/// Order is not significant; clients pick their own. Hidden mechanisms (e.g. STF) are
/// excluded — they surface only for users who already hold them — so this is the set that drives a
/// "purchase via …" store list.
std::span<const std::string_view> visible_platforms();

/// Endpoint + content-type + opaque payload for a request to be POSTed to the Session Pro backend,
/// returned by the `*_request()` helpers below. Callers relay `data` verbatim under `content_type`
/// and never inspect or assume its format -- libsession owns the wire encoding.
struct ProRequest {
    /// Endpoint path relative to the backend base URL, e.g. "generate_pro_proof". As returned from
    /// a
    /// `*_request()` function this points at a static, null-terminated string, so using
    /// `endpoint.data()` as a C string is valid.
    std::string_view endpoint;

    /// Content type to send as the request's `Content-Type` header. Points at a static,
    /// null-terminated string. Clients MUST relay this verbatim and MUST NOT assume a particular
    /// format: `data` is libsession's opaque payload for the backend and libsession owns the wire
    /// encoding, which may change without client involvement.
    std::string_view content_type;

    /// The opaque request payload to POST to `endpoint`. This is libsession's data for the backend;
    /// clients relay it untouched and must not parse, inspect, or modify it.
    std::string data;
};

/// Response to `pro_proof_request` (endpoint `generate_pro_proof`): carries the freshly-issued
/// Session Pro proof. `proof` is the raw parse result, convertible to a config::ProProof.
struct GenerateProProofResponse : ResponseBase {
    ProProof proof;

    /// The end of the paid term -- the same value `get_pro_status` reports as its `expiry_ts`
    /// (pro-wire-protocol.md §2.2), carrying neither the store's grace nor the backend's
    /// renewal-latency allowance; coverage runs to `account_expiry + account_grace_period`.
    /// Advisory and UNSIGNED: not part of the proof's signed message and never fed into signature
    /// verification; it rides on the response so a proof fetch also refreshes the client's cached
    /// access expiry. Distinct from `proof.expiry_at` (the clamped, rolling <=30d proof-validity
    /// window). Present (and required) on a successful proof, and on a `subscription_expired`
    /// failure (a now-past value carried top-level on the envelope); nullopt on other outcomes
    /// (`not_subscribed`, `revoked`, protocol errors).
    std::optional<std::chrono::sys_seconds> account_expiry;

    /// How much longer the account keeps being served past `account_expiry` above -- the store's
    /// dunning window plus the backend's renewal-latency allowance -- so coverage ends at
    /// `account_expiry + account_grace_period`. Zero whenever the subscription is not
    /// auto-renewing, mirroring `get_pro_status`, because neither span applies to a term that is
    /// simply ending.
    ///
    /// Carried, alongside `account_auto_renewing`, on both a successful proof and a
    /// `subscription_expired` failure -- refresh all three of these together (see `account_expiry`)
    /// and never the expiry alone. `0` when the backend omits it, which it does whenever grace does
    /// not apply: a missing value means "not applicable" and should overwrite (clear) any stale
    /// cached grace, never be taken as "leave the old value". Consequently it is a truthful `0` on
    /// the account-less outcomes too (`not_subscribed`, `revoked`, protocol/transport errors).
    std::chrono::seconds account_grace_period{0};

    /// Whether the subscription behind `account_expiry` renews itself -- the same value
    /// `get_pro_status` reports as `auto_renewing`. Advisory and UNSIGNED, like the two above.
    ///
    /// Travels with `account_grace_period` (see there): carried on a successful proof and on a
    /// `subscription_expired` failure, `false` whenever the backend omits it. Refresh it together
    /// with the expiry and grace; a missing value means "not renewing" and should clear the
    /// presence-only config flag, not preserve a stale one.
    bool account_auto_renewing{false};
};

/// Parse the reply to a generate-proof request. On success `proof` holds the issued proof; a
/// well-formed backend failure is returned with `status`/`error_code` set. Throws `parse_error` if
/// the reply is malformed.
GenerateProProofResponse parse_pro_proof(std::string_view json);

/// Request a new Session Pro proof from the backend (endpoint `generate_pro_proof`). The master key
/// must have a still-active payment on record -- redemption is implicit, so any master-signed
/// request (this one included) binds the account's unbound payments before answering; there is no
/// separate "add payment" step. This pairs a (new) rotating key to a freshly-issued proof.
///
/// Builds the whole request, signing internally with the master and rotating keys, and returns the
/// endpoint + JSON body. Throws on an incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` / `rotating_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium private key
/// - `unix_ts` -- Unix timestamp for the request
ProRequest pro_proof_request(
        std::span<const uint8_t> master_privkey,
        std::span<const uint8_t> rotating_privkey,
        sys_seconds unix_ts);

/// Build a request for the current Session Pro revocation list (endpoint `get_pro_revocations`).
/// This request is unsigned. The caller retains each returned item for the response's `retain_for`
/// window after first seeing it (memory-only aging) and polls again after `retry_in`.
///
/// Inputs:
/// - `ticket` -- 64-bit monotonic revocation-list iteration. Pass 0 if unknown; otherwise the
/// latest
///   known `ticket` from a prior `GetProRevocationsResponse`, so the backend may omit an unchanged
///   list.
ProRequest revocations_request(std::int64_t ticket);

struct ProRevocationItem {
    /// 32-byte opaque revocation tag identifying a proof
    array_uc32 revocation_tag;

    /// A matching proof is revoked once the client's clock reaches this unix timestamp (not before)
    sys_seconds effective_at;
};

struct GetProRevocationsResponse : ResponseBase {
    /// 64-bit monotonic integer for the latest revocation list iteration.
    /// Update the caller's ticket to this value for subsequent requests.
    std::int64_t ticket;

    /// Recommended interval to wait before polling the revocation list again.
    std::chrono::seconds retry_in;

    /// How long a client should retain each item after first seeing it, for memory-only local
    /// aging (roughly the maximum proof-validity window). Applied as `seen + retain_for`; holding
    /// an entry longer is harmless.
    std::chrono::seconds retain_for;

    /// List of revoked Session Pro proofs
    std::vector<ProRevocationItem> items;
};

/// Parse the reply to a `revocations_request`. A well-formed backend failure is returned with
/// `status`/`error_code` set. Throws `parse_error` if the reply is malformed.
GetProRevocationsResponse parse_revocations(std::string_view json);

/// Query a master key's Session Pro status (endpoint `get_pro_status`): the account entitlement
/// state plus its single latest payment -- the hot "am I Pro?" path. Builds the whole request,
/// signing internally with the master key, and returns the endpoint + JSON body. Throws on an
/// incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium master private key
/// - `unix_ts` -- Unix timestamp for the request
ProRequest pro_status_request(std::span<const uint8_t> master_privkey, sys_seconds unix_ts);

/// Query a master key's Session Pro payment history (endpoint `get_payment_details`), one keyset
/// page at a time. Builds the whole request, signing internally with the master key, and returns
/// the endpoint + JSON body. Throws on an incorrectly-sized key.
///
/// Inputs:
/// - `master_privkey` -- 32-byte Ed25519 seed or 64-byte libsodium master private key
/// - `unix_ts` -- Unix timestamp for the request
/// - `limit` -- maximum payments to return on this page (the backend may clamp it)
/// - `before` -- opaque pagination cursor from a previous page's `next_cursor` (see
///   PaymentDetailsResponse); the empty string requests the newest page. Pass it through verbatim;
///   it must not be parsed or synthesized.
ProRequest payment_details_request(
        std::span<const uint8_t> master_privkey,
        sys_seconds unix_ts,
        uint32_t limit,
        std::string_view before);

/// Unit of a billing period (the `unit` of a parsed `plan` code, pro-wire-protocol.md §1). A closed
/// set: the backend emits only these, so an unrecognized code is a protocol error.
enum class ProPlanUnit { second, day, week, month, year, lifetime };

/// A parsed `plan` billing-period code. The `unit` is preserved exactly as transmitted and never
/// canonicalized ("12m" and "1y" are the same duration but distinct values). `count` is meaningful
/// only for the periodic units and is >= 1; for `lifetime` it is 0 (invariant: count == 0 iff unit
/// == lifetime), so consumers switch on `unit` and never render "<count> <unit>" for lifetime.
struct ProPlanPeriod {
    int count;
    ProPlanUnit unit;
};

/// Parse a `plan` billing-period code (pro-wire-protocol.md §1): "<N><unit>" with N a
/// positive integer (no leading zeros) and unit one of s/d/w/m/y (second/day/week/month/year), or
/// the literal "lifetime". Single-unit only ("1y6m" is invalid). Returns std::nullopt for any
/// non-conforming code (the caller treats that as a protocol error).
std::optional<ProPlanPeriod> parse_plan_period(std::string_view plan_code);

struct ProPaymentItem {
    /// Describes the current status of the consumption of the payment for Session Pro entitlement
    /// The status should be used to determine which timestamps should be used.
    ///
    /// For example, a payment can be in a redeemed state whilst also have a refunded timestamp set
    /// if the payment was refunded and then the refund was reversed. We preserve all timestamps for
    /// book-keeping purposes.
    std::string status;

    /// The parsed billing period that was purchased (e.g. "1m" -> {1, month}, "lifetime" -> {0,
    /// lifetime}). libsession parses the closed `plan` grammar (§1); the client just
    /// localizes the display. The unit is preserved as transmitted, never canonicalized.
    ProPlanPeriod plan;

    /// Provider code this payment came from (e.g. "google_play"); opaque -- an unknown value passes
    /// through as-is for the client to handle.
    std::string payment_provider;

    /// Flag indicating whether or not this payment will automatically bill itself at the end of the
    /// billing cycle.
    bool auto_renewing;

    /// Provider purchase time (when the upstream provider recorded the purchase). Always set.
    /// Carries the provider's sub-second precision as a millisecond-resolution `sys_ms`; the wire
    /// sends it as a float of seconds.
    sys_ms purchased_at;

    /// Unix timestamp of when the payment was expiry. 0 if not activated
    sys_seconds expiry_at;

    /// The dunning window this ONE payment's provider declared -- raw store data, and NOT the same
    /// quantity as `ProStatusResponse::grace_period_duration`, which is account-level and adds the
    /// backend's renewal-latency allowance. This one is also not gated on `auto_renewing`, so a
    /// cancelled subscription can still carry a stale non-zero value here.
    ///
    /// Use the account-level field for "when does entitlement end"; this is for showing what a
    /// given payment was granted. Only meaningful when this payment's `auto_renewing` is true.
    std::chrono::seconds grace_period_duration;

    /// Unix deadline timestamp of when the user is able to refund the subscription via the payment
    /// provider. Thereafter the user must initiate a refund manually via Session support.
    sys_seconds platform_refund_expiry_at;

    /// Provider revocation instant (when the payment was revoked). Epoch (0) if not applicable.
    /// Carries the provider's sub-second precision as a millisecond-resolution `sys_ms`; the wire
    /// sends it as a float of seconds.
    sys_ms revoked_at;

    /// Opaque, backend-owned payment identifier (§5.2). Store and compare it for equality, but
    /// never parse it -- libsession does not interpret it. Confidential; store appropriately.
    std::string payment_id;
};

struct ProStatusResponse : ResponseBase {
    /// Current Session Pro entitlement status for the master public key
    /// ("never"/"active"/"expired"; opaque -- an unknown value passes through as-is).
    std::string user_status;

    /// The single most-recent payment for the master public key, or std::nullopt when the account
    /// has no payments. (The full payment history is a separate query -- parse_payment_details.)
    std::optional<ProPaymentItem> latest_payment;

    /// Flag to indicate if the user will automatically renew their subscription.
    bool auto_renewing;

    /// The account's PAYMENT-DUE date: the instant the current term was paid through. This does
    /// NOT include the grace period -- entitlement continues to `expiry_at +
    /// grace_period_duration`, and the backend judges `user_status` against that sum rather than
    /// against this value.
    ///
    /// So `expiry_at` alone answers "when is the next payment due", and `[expiry_at,
    /// expiry_at + grace_period_duration)` is the window where the payment is overdue but service
    /// continues. Do not subtract the grace from this -- that was the shape before the backend
    /// stopped folding grace into the stored expiry, and it now yields an instant that means
    /// nothing.
    ///
    /// This timestamp may be in the past if the user no longer has active payments. Overtime the
    /// Pro Backend may prune user history and so after long lapses of activity, a user's
    /// subscription history may be deleted.
    sys_seconds expiry_at;

    /// How much longer entitlement continues PAST `expiry_at`: the payment provider's dunning
    /// window (the leeway it allows itself to retry a failed renewal) plus the backend's own
    /// renewal-latency allowance, which covers the gap between a term ending and the backend
    /// learning whether it renewed.
    ///
    /// Add it to `expiry_at` to get the instant entitlement actually ends. 0 when `auto_renewing`
    /// is false, because neither span applies to a term that is simply ending -- so the sum is
    /// still correct there without a special case.
    std::chrono::seconds grace_period_duration;
};

struct PaymentDetailsResponse : ResponseBase {
    /// One keyset page of the master public key's payment history, newest-first (at most the
    /// `limit` passed to payment_details_request).
    std::vector<ProPaymentItem> items;

    /// Total number of payments known by the backend for the user. This may be greater than the
    /// length of `items` when the requested page did not cover the full history.
    uint32_t payments_total;

    /// Opaque keyset-pagination cursor for the next (older) page: re-request with this value as
    /// `before` to continue, and stop when it is std::nullopt (end-of-data). Store and echo it
    /// verbatim -- it is an encrypted token and MUST NOT be parsed or synthesized (a tampered or
    /// foreign cursor is rejected). (pro-wire-protocol.md §5.3.)
    std::optional<std::string> next_cursor;
};

/// Parse the reply to a `pro_status_request`. A well-formed backend failure is returned with
/// `status`/`error_code` set. Throws `parse_error` if the reply is malformed.
ProStatusResponse parse_pro_status(std::string_view json);

/// Parse the reply to a `payment_details_request`. A well-formed backend failure is returned with
/// `status`/`error_code` set. Throws `parse_error` if the reply is malformed.
PaymentDetailsResponse parse_payment_details(std::string_view json);
}  // namespace session::pro_backend
