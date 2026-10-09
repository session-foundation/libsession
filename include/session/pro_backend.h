#pragma once

#include <session/session_protocol.h>
#include <session/types.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Canonical payment-provider `code` strings — the `payment_provider` value the backend reports on
/// a payment item (§5.2) and the slug clients key their store/display logic on. Reference these
/// rather than hardcoding the slug so client code cannot drift from what libsession parses. Unknown
/// codes (e.g. a future provider) are still valid on the wire and pass through as opaque strings.
/// Each points at the C++ `session::pro_backend::PAYMENT_PROVIDER_*` value (defined there — the
/// primary; C references).
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_STF;

/// Endpoint path (relative to the backend base URL) that each request type is POSTed to. libsession
/// owns the body<->route pairing, so reference these rather than hardcoding the path client-side.
/// The C++ `*_request()` helpers return the matching endpoint alongside the body; C callers read
/// the constant beside each request's build function. Each is a pointer to the single master string
/// owned in the C++ implementation (defined once, shared by the C and C++ sides).
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_STATUS_ENDPOINT;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PAYMENT_DETAILS_ENDPOINT;
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT;

/// The Session Pro Backend's production base URL (POST a request body to `<URL>/<endpoint>`).
/// Canonical production value; clients may override with a dev/test server. Points at the single
/// master string owned in the C++ implementation.
LIBSESSION_EXPORT extern const char* const SESSION_PRO_BACKEND_URL;

/// The Session Pro Backend's Ed25519 public signing key, 32 bytes, for verifying a proof was issued
/// by the backend. Points at the same value as the C++ `session::pro_backend::PUBKEY`.
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY;

/// The X25519 form of SESSION_PRO_BACKEND_PUBKEY, 32 bytes (the Ed25519 key converted via
/// crypto_sign_ed25519_pk_to_curve25519). Points at the same value as the C++
/// `session::pro_backend::PUBKEY_X25519`.
LIBSESSION_EXPORT extern const unsigned char* const SESSION_PRO_BACKEND_PUBKEY_X25519;

/// Per-provider support/management URLs, keyed by provider code. These are identical for every user
/// (not translation data), so libsession owns them as the single source of truth rather than each
/// client duplicating them; the human-readable provider/store names are translation data and remain
/// the client's job. Each URL field is NULL when that provider has no such URL, and is otherwise a
/// static, null-terminated C string. Use `found` (not the URL fields) to tell an unknown provider
/// code from a known provider that simply has no URLs.
typedef struct session_pro_backend_provider_urls {
    /// True if `provider_code` is a recognised provider; false if it is unknown (or e.g.
    /// STF), in which case every URL field below is NULL. A recognised provider may still
    /// leave any or all URL fields NULL.
    bool found;
    const char* refund_platform_url;      /// Native store refund flow
    const char* refund_support_url;       /// Session support page for requesting a refund
    const char* refund_status_url;        /// Where a user checks refund status
    const char* update_subscription_url;  /// Manage/update the subscription
    const char* cancel_subscription_url;  /// Cancel the subscription
} session_pro_backend_provider_urls;

/// API: session_pro_backend/get_provider_urls
///
/// Returns the support/management URLs for `provider_code` (a
/// SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_* value). On an unrecognised code the result has
/// `found == false` and all URL fields NULL; on a recognised code `found == true` and each URL
/// field is either a static, null-terminated C string or NULL if that provider lacks that URL.
LIBSESSION_EXPORT session_pro_backend_provider_urls
session_pro_backend_get_provider_urls(const char* provider_code) NON_NULL_ARG(1);

/// API: session_pro_backend/visible_platforms
///
/// Returns the user-visible purchasable platforms as an array of `*count` provider-code C strings
/// (a subset of the SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_* values). Order is not significant;
/// clients pick their own. Hidden mechanisms (e.g. STF) are excluded. The returned array and
/// its strings are static storage owned by libsession — do not free.
LIBSESSION_EXPORT const char* const* session_pro_backend_visible_platforms(size_t* count);

/// A built request to POST to the Session Pro backend. Mirrors the C++
/// `session::pro_backend::ProRequest`: an `endpoint`, the `content_type` to send as the request's
/// Content-Type header, and the opaque `data` payload. `data` is libsession's data for the backend
/// -- relay it verbatim with the given `content_type` and do NOT parse, inspect, or assume a format
/// for it. libsession owns the wire encoding and may change it without client involvement.
typedef struct session_pro_backend_request {
    char error[256];
    size_t error_count;
    bool success;  /// True if the request was built successfully, false if out-of-memory
    /// Endpoint path (relative to the backend base URL) to POST to; static, null-terminated string.
    const char* endpoint;
    /// Value for the request's Content-Type header; static, null-terminated string. Relay verbatim.
    const char* content_type;
    /// The opaque request payload (raw bytes). Relay untouched; do not parse or modify.
    span_u8 data;
    /// Owned C++ object backing endpoint/content_type/data; do not touch (freed by request_free).
    void* internal_;
} session_pro_backend_request;

/// API: session_pro_backend/request_free
///
/// Frees a `session_pro_backend_request` returned by a `*_request_build` function.
LIBSESSION_EXPORT
void session_pro_backend_request_free(session_pro_backend_request* request);

/// Response outcome (wire `status`, spec §5). CLOSED/exhaustive: the backend will never add a
/// value, so an unrecognized wire status is reported as a protocol error (RESPONSE_STATUS_ERROR +
/// error_code "invalid_response"). Mirrors C++ session::pro_backend::ResponseStatus.
typedef enum SESSION_PRO_BACKEND_RESPONSE_STATUS {
    SESSION_PRO_BACKEND_RESPONSE_STATUS_OK,     ///< Success; the response's payload fields are set.
    SESSION_PRO_BACKEND_RESPONSE_STATUS_FAIL,   ///< Rejected on client input / a precondition.
    SESSION_PRO_BACKEND_RESPONSE_STATUS_ERROR,  ///< Backend fault; the same request may succeed
                                                ///< later.
} SESSION_PRO_BACKEND_RESPONSE_STATUS;

typedef struct session_pro_backend_response_header {
    /// Outcome category. Success iff `status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK`.
    SESSION_PRO_BACKEND_RESPONSE_STATUS status;
    /// On non-OK, the machine-readable outcome slug (spec §5.1); NULL on success. Opaque and
    /// forward-compatible (unknown slugs pass through); "invalid_response" if libsession could not
    /// parse the reply at all. NUL-terminated; valid until the response is freed.
    const char* error_code;
    /// On non-OK, an English diagnostic string (NOT user-facing text -- that comes from mapping
    /// error_code to a localized string); NULL on success. Always safe to log. NUL-terminated;
    /// valid until the response is freed.
    const char* error;
    /// Opaque implementation detail; do not touch. Released by the response's *_free function.
    void* internal_;
} session_pro_backend_response_header;

typedef struct session_pro_backend_pro_proof_response {
    session_pro_backend_response_header header;
    session_protocol_pro_proof proof;
    /// The end of the paid term (unix seconds) -- coverage runs to this plus the grace below -- or
    /// 0 if this response carries no horizon. Advisory and unsigned (pro-wire-protocol.md §2.2):
    /// use for display / refreshing the cached access expiry only -- NOT an entitlement authority
    /// and NOT part of the proof signature. Distinct from `proof.expiry_ts` (the clamped <=30d
    /// proof-validity window). Populated on a successful proof and on a `subscription_expired`
    /// failure (a now-past value); 0 on `not_subscribed` / `revoked` / protocol errors.
    int64_t account_expiry_ts;
    /// How much longer (seconds) the account keeps being served past `account_expiry_ts`, so
    /// coverage ends at `account_expiry_ts + account_grace_period_duration`. 0 when the
    /// subscription is not auto-renewing.
    ///
    /// Carried with `account_auto_renewing` on a successful proof and on a `subscription_expired`
    /// failure -- refresh all three together (see `account_expiry_ts`), never the expiry alone. 0
    /// when the backend omits it (grace not applicable), so a refresh clears any stale cached grace
    /// rather than preserving it; likewise a truthful 0 on `not_subscribed` / `revoked` / errors.
    int64_t account_grace_period_duration;
    /// Whether the subscription behind `account_expiry_ts` renews itself. Travels with
    /// `account_grace_period_duration`: carried on a successful proof and a `subscription_expired`
    /// failure, false when the backend omits it. Refresh it with the expiry and grace; a false
    /// clears the presence-only config flag rather than preserving a stale one.
    bool account_auto_renewing;
} session_pro_backend_pro_proof_response;

/// API: session_pro_backend/pro_proof_response_free
///
/// Frees the response.
LIBSESSION_EXPORT
void session_pro_backend_pro_proof_response_free(session_pro_backend_pro_proof_response* response);

typedef struct session_pro_backend_pro_revocation_item {
    /// 32-byte revocation tag (compare for equality against a proof's tag); valid until the
    /// response is freed.
    const unsigned char* revocation_tag;
    /// Unix timestamp (seconds); a matching proof is revoked once the client clock reaches this
    int64_t effective_ts;
} session_pro_backend_pro_revocation_item;

typedef struct session_pro_backend_get_pro_revocations_response {
    session_pro_backend_response_header header;
    int64_t ticket;
    int64_t retry_in;    /// Recommended seconds to wait before polling the list again
    int64_t retain_for;  /// Seconds to retain each item after first seeing it (memory-only aging)
    /// Array of items, with items_count elements
    session_pro_backend_pro_revocation_item* items;
    size_t items_count;
} session_pro_backend_get_pro_revocations_response;

/// API: session_pro_backend/get_pro_revocations_response_free
///
/// Frees the response.
LIBSESSION_EXPORT
void session_pro_backend_get_pro_revocations_response_free(
        session_pro_backend_get_pro_revocations_response* response);

/// Unit of a parsed billing period (`plan_unit` below); mirrors C++
/// session::pro_backend::ProPlanUnit (same order). A closed set (pro-wire-protocol.md §1).
typedef enum SESSION_PRO_BACKEND_PLAN_UNIT {
    SESSION_PRO_BACKEND_PLAN_UNIT_SECOND,
    SESSION_PRO_BACKEND_PLAN_UNIT_DAY,
    SESSION_PRO_BACKEND_PLAN_UNIT_WEEK,
    SESSION_PRO_BACKEND_PLAN_UNIT_MONTH,
    SESSION_PRO_BACKEND_PLAN_UNIT_YEAR,
    SESSION_PRO_BACKEND_PLAN_UNIT_LIFETIME,
} SESSION_PRO_BACKEND_PLAN_UNIT;

typedef struct session_pro_backend_pro_payment_item {
    /// Opaque payment lifecycle status code (e.g. "redeemed"/"expired"/"revoked"); unknown values
    /// pass through as-is. NUL-terminated; points into the response's `internal_`.
    const char* status;
    /// Parsed billing period (pro-wire-protocol.md §1). `plan_count` is the period count
    /// (>= 1 for periodic units); for `plan_unit == ..._LIFETIME` it is 0 and not meaningful
    /// (switch on `plan_unit`, never render "<count> <unit>" for lifetime).
    int plan_count;
    SESSION_PRO_BACKEND_PLAN_UNIT plan_unit;
    /// Provider code (e.g. "google_play"); opaque -- an unknown value passes through as-is.
    /// NUL-terminated; points into the response's `internal_`.
    const char* payment_provider;

    bool auto_renewing;
    /// Provider purchase time, fractional UNIX seconds. Millisecond-precise: the value passes
    /// through a millisecond-resolution representation, so sub-millisecond digits are not retained.
    double purchased_ts;
    /// When THIS payment's term was paid through.
    int64_t expiry_ts;
    /// The dunning window this one payment's provider declared -- raw store data. NOT the same
    /// quantity as the account-level `grace_period_duration` on the status response, which adds the
    /// backend's renewal-latency allowance and is gated on the account renewing. This one is not
    /// gated, so a cancelled subscription can still carry a stale non-zero value. For "when does
    /// entitlement end", use the account-level field.
    int64_t grace_period_duration;
    int64_t platform_refund_expiry_ts;
    /// Provider revocation instant, fractional UNIX seconds (millisecond-precise; 0 if not revoked)
    double revoked_ts;

    /// Opaque, backend-owned payment identifier (§5.2): store and compare for equality, never
    /// parse. NUL-terminated; points into the response's `internal_`.
    const char* payment_id;
} session_pro_backend_pro_payment_item;

typedef struct session_pro_backend_get_pro_status_response {
    session_pro_backend_response_header header;
    /// Opaque account Pro status code ("never"/"active"/"expired"); unknown values pass through.
    /// NUL-terminated; points into the response's `internal_`.
    const char* status;
    bool auto_renewing;
    /// The account's PAYMENT-DUE date: when the current term was paid through. Does NOT include the
    /// grace period -- entitlement runs to `expiry_ts + grace_period_duration`, and `status` is
    /// judged against that sum. Do not subtract the grace from this.
    int64_t expiry_ts;
    /// How much longer (seconds) entitlement continues PAST `expiry_ts`: the provider's dunning
    /// window plus the backend's renewal-latency allowance. Add it to `expiry_ts` to get the
    /// instant entitlement ends; `[expiry_ts, expiry_ts + this)` is overdue-but-still-served. 0
    /// when `auto_renewing` is false, so the sum stays correct there without a special case.
    ///
    /// ACCOUNT-level. `latest_payment.grace_period_duration` shares the name and is a different
    /// quantity -- see there.
    int64_t grace_period_duration;
    /// True if the account has at least one payment, in which case `latest_payment` is populated
    /// with the most recent one; false means the account has no payments and `latest_payment` is
    /// unset.
    bool has_latest_payment;
    session_pro_backend_pro_payment_item latest_payment;
} session_pro_backend_get_pro_status_response;

/// API: session_pro_backend/get_pro_status_response_free
///
/// Frees the response.
LIBSESSION_EXPORT
void session_pro_backend_get_pro_status_response_free(
        session_pro_backend_get_pro_status_response* response);

typedef struct session_pro_backend_get_payment_details_response {
    session_pro_backend_response_header header;
    /// Array of payment items (one keyset page, newest-first), with items_count elements.
    session_pro_backend_pro_payment_item* items;
    size_t items_count;
    /// Total number of payments the backend knows for the user (may exceed items_count).
    uint32_t payments_total;
    /// Opaque keyset-pagination cursor: pass as `before` to
    /// session_pro_backend_get_payment_details_request_build to fetch the next (older) page. NULL
    /// at end-of-data. NUL-terminated and points into the response's `internal_`; echo it verbatim,
    /// do NOT parse or synthesize it.
    const char* next_cursor;
} session_pro_backend_get_payment_details_response;

/// API: session_pro_backend/get_payment_details_response_free
///
/// Frees the response.
LIBSESSION_EXPORT
void session_pro_backend_get_payment_details_response_free(
        session_pro_backend_get_payment_details_response* response);

/// API: session_pro_backend/generate_pro_proof_request_build
///
/// Builds the generate-proof request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`. On a key-size
/// error `success` is false and `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `rotating_privkey` / `rotating_privkey_len` -- Ed25519 rotating private key (32 or 64-byte).
/// - `ts` -- Unix timestamp (seconds) for the request.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_generate_pro_proof_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        const uint8_t* rotating_privkey,
        size_t rotating_privkey_len,
        int64_t ts) NON_NULL_ARG(1, 3);

/// API: session_pro_backend/get_pro_revocations_request_build
///
/// Builds the get-revocations request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`.
///
/// Inputs:
/// - `ticket` -- revocation-list ticket to resume from (0 for a full list).
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_get_pro_revocations_request_build(int64_t ticket);

/// API: session_pro_backend/get_pro_status_request_build
///
/// Builds the get-pro-status request to POST, as a session_pro_backend_request (endpoint +
/// content_type + opaque data). Free it with `session_pro_backend_request_free`. On a key-size
/// error `success` is false and `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `ts` -- Unix timestamp (seconds) for the request.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_get_pro_status_request_build(
        const uint8_t* master_privkey, size_t master_privkey_len, int64_t ts) NON_NULL_ARG(1);

/// API: session_pro_backend/get_payment_details_request_build
///
/// Builds the get-payment-details (paginated history) request to POST, as a
/// session_pro_backend_request (endpoint + content_type + opaque data). Free it with
/// `session_pro_backend_request_free`. On a key-size error `success` is false and
/// `error`/`error_count` describe it.
///
/// Inputs:
/// - `master_privkey` / `master_privkey_len` -- Ed25519 master private key (32 or 64-byte
/// libsodium).
/// - `ts` -- Unix timestamp (seconds) for the request.
/// - `limit` -- maximum payments to return on this page (the backend may clamp it).
/// - `before` -- opaque pagination cursor from a previous response's `next_cursor`, or NULL / the
///   empty string for the newest page. Pass through verbatim; do not parse or synthesize it.
LIBSESSION_EXPORT
session_pro_backend_request session_pro_backend_get_payment_details_request_build(
        const uint8_t* master_privkey,
        size_t master_privkey_len,
        int64_t ts,
        uint32_t limit,
        const char* before) NON_NULL_ARG(1);

/// API: session_pro_backend/pro_proof_response_parse
///
/// Parses a JSON string into an `pro_proof_response` struct.
/// The caller must free the response using
/// `session_pro_backend_pro_proof_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_pro_proof_response session_pro_backend_pro_proof_response_parse(
        const char* json, size_t json_len);

/// API: session_pro_backend/get_pro_revocations_response_parse
///
/// Parses a JSON string into a `session_pro_backend_get_pro_revocations_response` struct.
/// The caller must free the response using `session_pro_backend_get_pro_revocations_response_free`.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_pro_revocations_response
session_pro_backend_get_pro_revocations_response_parse(const char* json, size_t json_len);

/// API: session_pro_backend/get_pro_status_response_parse
///
/// Parses a JSON string into a session_pro_backend_get_pro_status_response struct.
/// The caller must free the response using session_pro_backend_get_pro_status_response_free.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_pro_status_response session_pro_backend_get_pro_status_response_parse(
        const char* json, size_t json_len);

/// API: session_pro_backend/get_payment_details_response_parse
///
/// Parses a JSON string into a session_pro_backend_get_payment_details_response struct.
/// The caller must free the response using session_pro_backend_get_payment_details_response_free.
///
/// Inputs:
/// - `json` -- JSON string to parse.
/// - `json_len` -- Length of the JSON string.
LIBSESSION_EXPORT
session_pro_backend_get_payment_details_response
session_pro_backend_get_payment_details_response_parse(const char* json, size_t json_len);

#ifdef __cplusplus
}  // extern "C"
#endif
