#include <oxenc/hex.h>
#include <session/pro_backend.h>
#include <sodium.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/pro_backend.hpp>
#include <string>

#include "utils.hpp"

using namespace session::pro_backend;

// NOTE: This is defined in main.cpp because it accepts a value from the CLI
extern std::string g_test_pro_backend_dev_server_url;

static bool span_u8_equals(span_u8 s, std::string_view str) {
    return std::string_view{reinterpret_cast<const char*>(s.data), s.size} == str;
}
TEST_CASE("Pro Backend C API", "[pro_backend]") {
    // Setup: Generate keys and payment token hash
    bytes32 master_pubkey = {};
    bytes64 master_privkey = {};
    crypto_sign_ed25519_keypair(master_pubkey.data, master_privkey.data);

    bytes32 rotating_pubkey = {};
    bytes64 rotating_privkey = {};
    crypto_sign_ed25519_keypair(rotating_pubkey.data, rotating_privkey.data);

    {
        int64_t unix_ts = 1698765432;  // Arbitrary timestamp (unix epoch seconds)

        // Opaque, backend-owned payment identifier as it appears on a payment item (§5.2): the
        // client stores and compares it for equality but never parses it.
        std::string fake_payment_id = "DEV.opaque-payment-id-0123456789";

        SECTION("session_pro_backend_generate_pro_proof_request_build") {
            auto result = session_pro_backend_generate_pro_proof_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data),
                    unix_ts);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = pro_proof_request(
                        master_privkey.data,
                        rotating_privkey.data,
                        session::as_sys_seconds(unix_ts));
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT);
                REQUIRE(span_u8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);

            // Invalid rotating key size
            result = session_pro_backend_generate_pro_proof_request_build(
                    master_privkey.data,
                    sizeof(master_privkey.data),
                    rotating_privkey.data,
                    sizeof(rotating_privkey.data) - 1,
                    unix_ts);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_get_pro_revocations_request_build") {
            auto result = session_pro_backend_get_pro_revocations_request_build(123);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = revocations_request(123);
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PRO_REVOCATIONS_ENDPOINT);
                REQUIRE(span_u8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);
        }

        SECTION("session_pro_backend_get_pro_status_request_build") {
            auto result = session_pro_backend_get_pro_status_request_build(
                    master_privkey.data, sizeof(master_privkey.data), unix_ts);
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp =
                        pro_status_request(master_privkey.data, session::as_sys_seconds(unix_ts));
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PRO_STATUS_ENDPOINT);
                REQUIRE(span_u8_equals(result.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);

            // Invalid key size
            result = session_pro_backend_get_pro_status_request_build(
                    master_privkey.data, sizeof(master_privkey.data) - 1, unix_ts);
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_get_payment_details_request_build") {
            auto result = session_pro_backend_get_payment_details_request_build(
                    master_privkey.data, sizeof(master_privkey.data), unix_ts, 100, "");
            {
                scope_exit result_free{[&]() { session_pro_backend_request_free(&result); }};
                REQUIRE(result.success);
                REQUIRE(result.data.size > 0);

                auto cpp = payment_details_request(
                        master_privkey.data, session::as_sys_seconds(unix_ts), 100, "");
                REQUIRE(std::string_view(result.endpoint) == cpp.endpoint);
                REQUIRE(cpp.endpoint == SESSION_PRO_BACKEND_GET_PAYMENT_DETAILS_ENDPOINT);
                REQUIRE(span_u8_equals(result.data, cpp.data));

                // A NULL cursor is equivalent to the empty (newest-page) cursor.
                auto result_null = session_pro_backend_get_payment_details_request_build(
                        master_privkey.data, sizeof(master_privkey.data), unix_ts, 100, nullptr);
                scope_exit result_null_free{
                        [&]() { session_pro_backend_request_free(&result_null); }};
                REQUIRE(result_null.success);
                REQUIRE(span_u8_equals(result_null.data, cpp.data));
            }
            REQUIRE(result.data.data == nullptr);

            // Invalid key size
            result = session_pro_backend_get_payment_details_request_build(
                    master_privkey.data, sizeof(master_privkey.data) - 1, unix_ts, 100, "");
            REQUIRE(!result.success);
            REQUIRE(result.error_count > 0);
        }

        SECTION("session_pro_backend_pro_proof_response_parse") {
            std::array<uint8_t, 32> fake_revocation_tag;
            randombytes_buf(fake_revocation_tag.data(), fake_revocation_tag.size());

            nlohmann::json j;
            j["status"] = "ok";
            j["result"] = {
                    {"expiry_ts", unix_ts},
                    {"revocation_tag", oxenc::to_hex(fake_revocation_tag)},
                    {"rotating_pkey", oxenc::to_hex(rotating_pubkey.data)},
                    {"sig", oxenc::to_hex(master_privkey.data)},
                    {"account_expiry_ts", unix_ts + 90 * 24 * 3600},
                    {"account_grace_period_duration", 14 * 24 * 3600},
                    {"account_auto_renewing", true}};
            std::string json = j.dump();

            // Valid JSON
            session_pro_backend_pro_proof_response result =
                    session_pro_backend_pro_proof_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_pro_proof_response_free(&result); }};

                if (result.header.error)
                    INFO(result.header.error);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error == nullptr);
                REQUIRE(result.proof.expiry_ts == unix_ts);
                REQUIRE(std::memcmp(
                                result.proof.revocation_tag.data,
                                fake_revocation_tag.data(),
                                fake_revocation_tag.size()) == 0);
                REQUIRE(std::memcmp(
                                result.proof.rotating_pubkey.data,
                                rotating_pubkey.data,
                                sizeof(rotating_pubkey.data)) == 0);
                REQUIRE(std::memcmp(
                                result.proof.sig.data,
                                master_privkey.data,
                                sizeof(master_privkey.data)) == 0);

                // Here we also create the CPP version, we will run the conversion functions into
                // pro proofs (both C and CPP variants) and then compare the two structures to make
                // sure the conversion functions are sound.
                auto result_cpp = parse_pro_proof(json);

                // Validate C and CPP variants
                REQUIRE(std::memcmp(
                                result.proof.revocation_tag.data,
                                result_cpp.proof.revocation_tag.data(),
                                result_cpp.proof.revocation_tag.size()) == 0);
                REQUIRE(std::memcmp(
                                result.proof.rotating_pubkey.data,
                                result_cpp.proof.rotating_pubkey.data(),
                                result_cpp.proof.rotating_pubkey.size()) == 0);
                REQUIRE(result.proof.expiry_ts ==
                        result_cpp.proof.expiry_at.time_since_epoch().count());
                REQUIRE(std::memcmp(
                                result.proof.sig.data,
                                result_cpp.proof.sig.data(),
                                result_cpp.proof.sig.size()) == 0);

                // account_expiry_ts (advisory, unsigned): surfaced by both the C and C++ parses,
                // and distinct from the proof's own expiry_ts.
                REQUIRE(result.account_expiry_ts == unix_ts + 90 * 24 * 3600);
                REQUIRE(result_cpp.account_expiry.has_value());
                REQUIRE(result_cpp.account_expiry->time_since_epoch().count() ==
                        result.account_expiry_ts);

                // Required on success: a proof response missing it is treated as malformed.
                nlohmann::json j_no_ae = j;
                j_no_ae["result"].erase("account_expiry_ts");
                REQUIRE_THROWS_AS(parse_pro_proof(j_no_ae.dump()), session::parse_error_missing);

                // The two fields that QUALIFY account_expiry_ts: both surface through the C and
                // C++ parses, and `E + G` is the instant coverage ends.
                REQUIRE(result_cpp.account_grace_period.count() == 14 * 24 * 3600);
                REQUIRE(result_cpp.account_auto_renewing);
                REQUIRE((*result_cpp.account_expiry + result_cpp.account_grace_period)
                                .time_since_epoch()
                                .count() == unix_ts + 90 * 24 * 3600 + 14 * 24 * 3600);
                REQUIRE(result.account_grace_period_duration == 14 * 24 * 3600);
                REQUIRE(result.account_auto_renewing);

                // Absent -> not applicable, defaulting to 0/false: never a throw, and never
                // preserving a stale value. The backend omits these when grace/renewal don't apply,
                // and a client refreshes all three together, so absence clears the cached
                // grace/flag rather than keeping it. A present value is parsed; the other,
                // still-present one is untouched.
                {
                    nlohmann::json j_no_grace = j;
                    j_no_grace["result"].erase("account_grace_period_duration");
                    auto m = parse_pro_proof(j_no_grace.dump());
                    REQUIRE(static_cast<bool>(m));
                    REQUIRE(m.account_grace_period.count() == 0);
                    REQUIRE(m.account_auto_renewing);

                    nlohmann::json j_no_renew = j;
                    j_no_renew["result"].erase("account_auto_renewing");
                    m = parse_pro_proof(j_no_renew.dump());
                    REQUIRE(static_cast<bool>(m));
                    REQUIRE_FALSE(m.account_auto_renewing);
                    REQUIRE(m.account_grace_period.count() == 14 * 24 * 3600);
                }

                // A *present* value must still be well-formed: a wrong-typed field is a backend
                // bug, not "not applicable", so it is a hard parse error rather than a silent
                // default.
                nlohmann::json j_bad = j;
                j_bad["result"]["account_auto_renewing"] = 1;  // int, not bool
                REQUIRE_THROWS_AS(parse_pro_proof(j_bad.dump()), session::parse_error_type);

                // The non-auto-renewing account: a genuine zero grace, and `E + 0 == E`.
                nlohmann::json j_false = j;
                j_false["result"]["account_grace_period_duration"] = 0;
                j_false["result"]["account_auto_renewing"] = false;
                auto f_cpp = parse_pro_proof(j_false.dump());
                REQUIRE_FALSE(f_cpp.account_auto_renewing);
                REQUIRE(f_cpp.account_grace_period.count() == 0);

                // It also rides a subscription_expired failure, carrying the same three account
                // fields so the client refreshes all of them without a separate status call. A
                // lapse can still be auto-renewing: the store keeps retrying the renewal past the
                // grace window, so subscription_expired does NOT imply grace 0 / not-renewing --
                // the parser must surface whatever the backend sent, never assume defaults.
                nlohmann::json j_exp;
                j_exp["status"] = "fail";
                j_exp["error_code"] = "subscription_expired";
                j_exp["error"] = "expired";
                j_exp["account_expiry_ts"] = unix_ts - 24 * 3600;
                j_exp["account_grace_period_duration"] = 14 * 24 * 3600;
                j_exp["account_auto_renewing"] = true;
                auto exp = parse_pro_proof(j_exp.dump());
                REQUIRE(exp.error_code == "subscription_expired");
                REQUIRE(exp.account_expiry.has_value());
                REQUIRE(exp.account_expiry->time_since_epoch().count() == unix_ts - 24 * 3600);
                REQUIRE(exp.account_grace_period.count() == 14 * 24 * 3600);
                REQUIRE(exp.account_auto_renewing);

                // An account-less failure (not_subscribed here; likewise revoked,
                // protocol/transport errors) carries none of the three, so grace/renewal read as
                // their truthful "not applicable" defaults of 0 / false -- always definite and safe
                // to read, so a client refreshing config from them clears a stale grace/flag rather
                // than being told to preserve one.
                {
                    nlohmann::json j_fail;
                    j_fail["status"] = "fail";
                    j_fail["error_code"] = "not_subscribed";
                    j_fail["error"] = "no";
                    auto fail = parse_pro_proof(j_fail.dump());
                    REQUIRE_FALSE(static_cast<bool>(fail));
                    REQUIRE(fail.account_grace_period.count() == 0);
                    REQUIRE_FALSE(fail.account_auto_renewing);
                }

                // Other failures (e.g. not_subscribed) carry no horizon.
                nlohmann::json j_ns;
                j_ns["status"] = "fail";
                j_ns["error_code"] = "not_subscribed";
                j_ns["error"] = "no";
                auto ns = parse_pro_proof(j_ns.dump());
                REQUIRE(ns.error_code == "not_subscribed");
                REQUIRE_FALSE(ns.account_expiry.has_value());
            }

            // After freeing
            REQUIRE(result.header.internal_ == nullptr);
            REQUIRE(result.header.error == nullptr);
            REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);

            // Invalid JSON
            json = "{invalid}";
            result = session_pro_backend_pro_proof_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_pro_proof_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code != nullptr);
                REQUIRE(result.header.error_code != nullptr);
            }

            // After freeing
            session_pro_backend_pro_proof_response_free(&result);
            REQUIRE(result.header.internal_ == nullptr);

            // Null JSON
            result = session_pro_backend_pro_proof_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code != nullptr);
            REQUIRE(result.header.error_code != nullptr);

            // No need to free, as errors point to static memory
        }

        SECTION("session_pro_backend_get_pro_revocations_response_parse") {
            nlohmann::json j;
            j["status"] = "ok";
            j["result"]["ticket"] = 123;
            j["result"]["retry_in"] = 3600;
            j["result"]["retain_for"] = 2592000;
            j["result"]["items"] = nlohmann::json::array();

            std::array<uint8_t, 32> fake_revocation_tag;
            randombytes_buf(fake_revocation_tag.data(), fake_revocation_tag.size());

            auto obj = nlohmann::json::object();
            obj["effective_ts"] = unix_ts;
            obj["revocation_tag"] = oxenc::to_hex(fake_revocation_tag);
            j["result"]["items"].push_back(obj);

            std::string json = j.dump();

            // Valid JSON
            auto result = session_pro_backend_get_pro_revocations_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_revocations_response_free(&result); }};
                if (result.header.error)
                    INFO(result.header.error);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error == nullptr);
                REQUIRE(result.ticket == 123);
                REQUIRE(result.retry_in == 3600);
                REQUIRE(result.retain_for == 2592000);
                REQUIRE(result.items_count == 1);
                REQUIRE(result.items != nullptr);
                REQUIRE(result.items[0].effective_ts == unix_ts);
                REQUIRE(std::memcmp(
                                result.items[0].revocation_tag,
                                fake_revocation_tag.data(),
                                fake_revocation_tag.size()) == 0);
            }

            // After freeeing
            REQUIRE(result.header.internal_ == nullptr);
            REQUIRE(result.items == nullptr);
            REQUIRE(result.items_count == 0);

            // Invalid JSON
            json = "{invalid}";
            {
                result = session_pro_backend_get_pro_revocations_response_parse(
                        json.data(), json.size());
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_revocations_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code != nullptr);
                REQUIRE(result.header.error_code != nullptr);
            }

            // After freeing
            REQUIRE(result.header.internal_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_pro_revocations_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code != nullptr);
            REQUIRE(result.header.error_code != nullptr);
        }

        // A single payment item (shared by the get-pro-status latest_payment and the
        // get-payment-details items[] tests). purchased_ts/revoked_ts are floats on the wire
        // (sub-second precision); the rest are whole-second integers.
        auto make_payment_item = [&](std::string payment_id) {
            return nlohmann::json{
                    {"status", "redeemed"},
                    {"plan", "1m"},
                    {"payment_provider", SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY},
                    {"auto_renewing", false},
                    {"purchased_ts", unix_ts - 3600 + 0.5},
                    {"expiry_ts", unix_ts},
                    {"grace_period_duration", 1001},
                    {"platform_refund_expiry_ts", unix_ts + 1},
                    {"revoked_ts", unix_ts + 3600 + 0.75},
                    {"payment_id", std::move(payment_id)}};
        };
        auto check_payment_item = [&](const session_pro_backend_pro_payment_item& item,
                                      std::string_view payment_id) {
            REQUIRE(std::string_view(item.status) == "redeemed");
            REQUIRE(item.plan_count == 1);
            REQUIRE(item.plan_unit == SESSION_PRO_BACKEND_PLAN_UNIT_MONTH);
            REQUIRE(std::string_view(item.payment_provider) ==
                    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY);
            // Sub-second precision preserved through sys_ms (0.5s = 500ms) round-trips exactly
            REQUIRE(item.purchased_ts == unix_ts - 3600 + 0.5);
            REQUIRE(item.expiry_ts == unix_ts);
            REQUIRE(item.grace_period_duration == 1001);
            REQUIRE(item.platform_refund_expiry_ts == unix_ts + 1);
            REQUIRE(item.revoked_ts == unix_ts + 3600 + 0.75);  // 750ms preserved
            REQUIRE(std::string_view(item.payment_id) == payment_id);
        };

        SECTION("session_pro_backend_get_pro_status_response_parse") {
            nlohmann::json j;
            j["status"] = "ok";
            j["result"] = {
                    {"user_status", "expired"},
                    {"auto_renewing", true},
                    {"expiry_ts", unix_ts + 2},
                    {"grace_period_duration", 1000},
                    {"latest_payment",
                     make_payment_item(
                             std::string(fake_payment_id.data(), fake_payment_id.size()))}};
            std::string json = j.dump();

            // Valid response with a latest payment
            auto result =
                    session_pro_backend_get_pro_status_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_status_response_free(&result); }};
                if (result.header.error)
                    INFO(result.header.error);

                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error == nullptr);
                REQUIRE(std::string_view(result.status) == "expired");
                REQUIRE(result.auto_renewing == true);
                REQUIRE(result.grace_period_duration == 1000);
                REQUIRE(result.expiry_ts == unix_ts + 2);
                REQUIRE(result.has_latest_payment);
                check_payment_item(result.latest_payment, fake_payment_id);
            }

            // A null latest_payment (account with no payments)
            j["result"]["latest_payment"] = nullptr;
            json = j.dump();
            auto result_empty =
                    session_pro_backend_get_pro_status_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_status_response_free(&result_empty); }};
                if (result_empty.header.error)
                    INFO(result_empty.header.error);
                REQUIRE(result_empty.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result_empty.has_latest_payment == false);
            }

            // After freeing
            REQUIRE(result.header.internal_ == nullptr);

            // Invalid JSON
            json = "{invalid}";
            result = session_pro_backend_get_pro_status_response_parse(json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_pro_status_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code != nullptr);
            }
            session_pro_backend_get_pro_status_response_free(&result);
            REQUIRE(result.header.internal_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_pro_status_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code != nullptr);
        }

        SECTION("session_pro_backend_get_payment_details_response_parse") {
            nlohmann::json j;
            j["status"] = "ok";
            j["result"] = {
                    {"payments_total", 3},
                    {"items",
                     nlohmann::json::array({make_payment_item(
                             std::string(fake_payment_id.data(), fake_payment_id.size()))})},
                    {"next_cursor", "opaque-cursor-token"}};
            std::string json = j.dump();

            // Valid page with a cursor
            auto result = session_pro_backend_get_payment_details_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_payment_details_response_free(&result); }};
                if (result.header.error)
                    INFO(result.header.error);

                REQUIRE(result.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error == nullptr);
                REQUIRE(result.payments_total == 3);
                REQUIRE(result.items_count == 1);
                REQUIRE(result.items != nullptr);
                check_payment_item(result.items[0], fake_payment_id);
                REQUIRE(result.next_cursor != nullptr);
                REQUIRE(std::string_view(result.next_cursor) == "opaque-cursor-token");
            }

            // End-of-data: null next_cursor, and payment_id is opaque so a different provider's
            // value passes through unchanged.
            j["result"]["items"][0]["payment_provider"] =
                    SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_STF;
            j["result"]["items"][0]["payment_id"] = "stf-opaque-id";
            j["result"]["next_cursor"] = nullptr;
            json = j.dump();
            auto result_end = session_pro_backend_get_payment_details_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{[&]() {
                    session_pro_backend_get_payment_details_response_free(&result_end);
                }};
                if (result_end.header.error)
                    INFO(result_end.header.error);
                REQUIRE(result_end.header.status == SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(std::string_view(result_end.items[0].payment_provider) ==
                        SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_STF);
                REQUIRE(std::string_view(result_end.items[0].payment_id) == "stf-opaque-id");
                REQUIRE(result_end.next_cursor == nullptr);  // end-of-data
            }

            // After freeing
            REQUIRE(result.header.internal_ == nullptr);
            REQUIRE(result.items == nullptr);
            REQUIRE(result.items_count == 0);

            // Invalid JSON
            json = "{invalid}";
            result = session_pro_backend_get_payment_details_response_parse(
                    json.data(), json.size());
            {
                scope_exit result_free{
                        [&]() { session_pro_backend_get_payment_details_response_free(&result); }};
                REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
                REQUIRE(result.header.error_code != nullptr);
            }
            session_pro_backend_get_payment_details_response_free(&result);
            REQUIRE(result.header.internal_ == nullptr);

            // Null JSON
            result = session_pro_backend_get_payment_details_response_parse(nullptr, 0);
            REQUIRE(result.header.status != SESSION_PRO_BACKEND_RESPONSE_STATUS_OK);
            REQUIRE(result.header.error_code != nullptr);
        }

        SECTION("Memory management edge cases") {
            // Test freeing null/empty structs
            session_pro_backend_request to_json = {};
            session_pro_backend_request_free(&to_json);
            REQUIRE(to_json.data.data == nullptr);
            REQUIRE(to_json.data.size == 0);

            session_pro_backend_pro_proof_response proof_response = {};
            session_pro_backend_pro_proof_response_free(&proof_response);
            REQUIRE(proof_response.header.internal_ == nullptr);

            session_pro_backend_get_pro_revocations_response rev_response = {};
            session_pro_backend_get_pro_revocations_response_free(&rev_response);
            REQUIRE(rev_response.header.internal_ == nullptr);

            session_pro_backend_get_pro_status_response status_response = {};
            session_pro_backend_get_pro_status_response_free(&status_response);
            REQUIRE(status_response.header.internal_ == nullptr);

            session_pro_backend_get_payment_details_response pay_response = {};
            session_pro_backend_get_payment_details_response_free(&pay_response);
            REQUIRE(pay_response.header.internal_ == nullptr);
        }
    }
}

TEST_CASE("Pro Backend X25519 pubkey matches the converted Ed25519 pubkey", "[pro_backend]") {
    // PUBKEY_X25519 is a hardcoded convenience constant; assert it equals the runtime conversion of
    // the Ed25519 PUBKEY so the two can never silently drift.
    unsigned char converted[32] = {};
    REQUIRE(crypto_sign_ed25519_pk_to_curve25519(converted, PUBKEY.data()) == 0);
    REQUIRE(std::memcmp(converted, PUBKEY_X25519.data(), sizeof(converted)) == 0);
    // The C export points at the same bytes.
    REQUIRE(std::memcmp(
                    SESSION_PRO_BACKEND_PUBKEY_X25519, PUBKEY_X25519.data(), sizeof(converted)) ==
            0);
}

TEST_CASE("Pro Backend visible_platforms lists purchasable stores, excludes stf", "[pro_backend]") {
    auto platforms = visible_platforms();
    auto has = [](std::span<const std::string_view> v, std::string_view s) {
        for (auto x : v)
            if (x == s)
                return true;
        return false;
    };
    REQUIRE(has(platforms, SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY));
    REQUIRE(has(platforms, SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE));
    // Hidden mechanisms are handled but never listed.
    REQUIRE_FALSE(has(platforms, SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_STF));
    REQUIRE(platforms.size() == 2);

    // The C export returns the same slugs, in the same order (it is derived from the C++ list).
    size_t count = 0;
    const char* const* c = session_pro_backend_visible_platforms(&count);
    REQUIRE(count == platforms.size());
    for (size_t i = 0; i < count; i++)
        REQUIRE(std::string_view{c[i]} == platforms[i]);
}

TEST_CASE("Pro Backend parse_plan_period (closed grammar)", "[pro_backend]") {
    using enum ProPlanUnit;
    auto ok = [](std::string_view code, int n, ProPlanUnit u) {
        auto p = parse_plan_period(code);
        REQUIRE(p.has_value());
        CHECK(p->count == n);
        CHECK(p->unit == u);
    };

    // Every unit; count preserved verbatim.
    ok("30s", 30, second);
    ok("14d", 14, day);
    ok("2w", 2, week);
    ok("1m", 1, month);
    ok("3m", 3, month);
    ok("1y", 1, year);
    // Unit is preserved, never canonicalized: "12m" stays (12, month), not (1, year).
    ok("12m", 12, month);
    // lifetime: count 0, and the invariant count == 0 iff unit == lifetime.
    ok("lifetime", 0, lifetime);

    // Non-conforming codes -> nullopt (caller treats as a protocol error; no raw pass-through).
    for (std::string_view bad :
         {"",
          "m",
          "1",
          "0m",
          "01m",
          "1y6m",
          "-1m",
          "+1m",
          "1x",
          "1 m",
          "1M",
          "1mm",
          "1.5m",
          "9999999999999999999m",
          "lifetime2",
          "Lifetime"})
        CHECK_FALSE(parse_plan_period(bad).has_value());
}

// ---------------------------------------------------------------------------
// Known-answer vectors (tag [pro_kat]) -- SERVER-LESS (runs in an ordinary testAll build).
//
// These pin libsession's signed-message construction (wire spec §1.1 / §2 / §3) to
// fixed byte vectors that were generated from the backend's *independent* implementation and then
// hand-verified against the spec layout (generator: tests/pro_backend/gen_kat.py). The live
// [pro_live] suite catches libsession<->backend *drift*; a KAT additionally catches a fault where
// BOTH sides share the same wrong construction (they would still agree with each other), needs no
// running backend, and freezes the wire format against silent future drift. Ed25519 is
// deterministic (RFC 8032), so a signature over a fixed message under a fixed key is itself a known
// answer.
//
// Fixed inputs: keypairs from 32-byte seeds 0x01.. / 0x02.. (backend key 0x03..), ts=1700000000,
// expiry=1704067200, count=10, revocation_tag=0x11 x32.
TEST_CASE("Pro backend known-answer vectors", "[pro_backend][pro_kat]") {
    auto keypair = [](unsigned char seed_byte) {
        std::array<unsigned char, 32> pk{};
        std::array<unsigned char, 64> sk{};
        std::array<unsigned char, 32> seed{};
        seed.fill(seed_byte);
        crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
        return std::pair{pk, sk};
    };
    auto [master_pk, master_sk] = keypair(0x01);
    auto [rotating_pk, rotating_sk] = keypair(0x02);
    auto [backend_pk, backend_sk] = keypair(0x03);
    (void)backend_sk;

    const auto ts = session::as_sys_seconds(1700000000);
    const auto expiry = session::as_sys_seconds(1704067200);

    // Expected signed-message bytes (hex), each hand-verified against the spec field layout.
    const std::string gen_msg_hex =
            "50726f47656e657261746550726f6f668a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488"
            "01"
            "b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39431373030303030"
            "303030";
    // The two read requests: get_pro_status (§3.2; master + ts) and paginated get_payment_details
    // (§3.3; master + ts + limit + before). Two details vectors pin the `before` framing: empty
    // `before` (newest page) ends in the adjacency \0; a non-empty cursor is the opaque final field
    // (no trailing separator).
    const std::string status_msg_hex =
            "50726f47657450726f5374617475735f8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488"
            "01b40f6f5c31373030303030303030";
    const std::string details_empty_msg_hex =
            "50726f47657450617944657461696c738a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488"
            "01b40f6f5c3137303030303030303000313000";
    const std::string details_cursor_msg_hex =
            "50726f47657450617944657461696c738a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf37488"
            "01b40f6f5c3137303030303030303000313000306131623263336434653566";
    const std::string proof_msg_hex =
            "50726f50726f6f665f76305f5f5f5f5f111111111111111111111111111111111111111111111111111111"
            "1111"
            "1111118139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3943137303430363732"
            "3030";

    // Assert `field`'s hex signature in request body `body` is a valid Ed25519 signature of the
    // expected message bytes under `pubkey` -- i.e. libsession signed *exactly* the spec message.
    auto sig_covers = [](const std::string& body,
                         const char* field,
                         const std::string& expected_msg_hex,
                         const std::array<unsigned char, 32>& pubkey) -> bool {
        auto j = nlohmann::json::parse(body);
        if (!j.contains(field))
            return false;
        auto sig = oxenc::from_hex(j.at(field).get<std::string>());
        auto msg = oxenc::from_hex(expected_msg_hex);
        return sig.size() == 64 && crypto_sign_verify_detached(
                                           reinterpret_cast<const unsigned char*>(sig.data()),
                                           reinterpret_cast<const unsigned char*>(msg.data()),
                                           msg.size(),
                                           pubkey.data()) == 0;
    };

    SECTION("generate_pro_proof") {
        auto req = pro_proof_request(master_sk, rotating_sk, ts);
        CHECK(req.endpoint == SESSION_PRO_BACKEND_GENERATE_PRO_PROOF_ENDPOINT);
        CHECK(sig_covers(req.data, "master_sig", gen_msg_hex, master_pk));
        CHECK(sig_covers(req.data, "rotating_sig", gen_msg_hex, rotating_pk));
    }
    SECTION("get_pro_status") {
        auto req = pro_status_request(master_sk, ts);
        CHECK(req.endpoint == SESSION_PRO_BACKEND_GET_PRO_STATUS_ENDPOINT);
        CHECK(sig_covers(req.data, "master_sig", status_msg_hex, master_pk));
    }
    SECTION("get_payment_details (newest page, empty before)") {
        auto req = payment_details_request(master_sk, ts, 10, "");
        CHECK(req.endpoint == SESSION_PRO_BACKEND_GET_PAYMENT_DETAILS_ENDPOINT);
        CHECK(sig_covers(req.data, "master_sig", details_empty_msg_hex, master_pk));
    }
    SECTION("get_payment_details (with cursor)") {
        auto req = payment_details_request(master_sk, ts, 10, "0a1b2c3d4e5f");
        CHECK(req.endpoint == SESSION_PRO_BACKEND_GET_PAYMENT_DETAILS_ENDPOINT);
        CHECK(sig_covers(req.data, "master_sig", details_cursor_msg_hex, master_pk));
    }
    SECTION("pro proof") {
        session::ProProof proof;
        std::memset(proof.revocation_tag.data(), 0x11, proof.revocation_tag.size());
        std::memcpy(proof.rotating_pubkey.data(), rotating_pk.data(), 32);
        proof.expiry_at = expiry;
        auto sig = oxenc::from_hex(
                "767e7f14cec2d04fb67c6407e890cbe6a5cfdb7a0df3e729adda93164b13bc3f"
                "b20ed4ea1b8f1ffc74115ff2598a51ac52285d923f0864c6bca08bfc771fb708");
        std::memcpy(proof.sig.data(), sig.data(), 64);

        // Direct pin of the proof (spec section 2) message construction.
        CHECK(oxenc::to_hex(proof.signed_message()) == proof_msg_hex);
        // The frozen backend signature (key 0x03 over that message) verifies; a wrong key does not.
        CHECK(proof.verify_signature(backend_pk));
        auto wrong = backend_pk;
        wrong[0] ^= 0x01;
        CHECK_FALSE(proof.verify_signature(wrong));
    }
}

#if defined(TEST_PRO_BACKEND_WITH_DEV_SERVER)
#include <curl/curl.h>

#include <cstdlib>
#include <functional>
#include <session/network/key_types.hpp>
#include <session/network/session_network_types.hpp>
#include <session/onionreq/builder.hpp>
#include <session/onionreq/response_parser.hpp>

size_t curl_perform_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* response_json = static_cast<std::string*>(userp);
    *response_json += std::string_view(static_cast<char*>(contents), total);
    return total;
};

std::string curl_do_basic_blocking_post_request(
        CURL* curl, curl_slist* headers, const std::string& url, std::string_view post_body) {
    std::string result;
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_perform_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    if (post_body.size()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_body.size());
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        INFO("ERROR: Post to " << url << " with " << post_body << ": " << curl_easy_strerror(res));
        REQUIRE(res == CURLE_OK);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Dev-server transport helpers.
//
// A transport delivers a Pro request body to a named endpoint on the running dev backend and
// returns the response body (JSON). We drive the identical libsession C++ request builders/parsers
// through each, so the same test flow can run over the two production request modes on pfs/dev:
//
//   * `make_direct_http_transport` -- plain HTTP POST to `<base>/<endpoint>`. This is the faithful
//     representation of session-router mode, where libsession opens a tunnel to a private local
//     address and makes unencrypted HTTP through it.
//   * `make_onion_v4_transport`    -- builds only the innermost v4 onion piece (a zero-hop
//     `onionreq::Builder` addressed to the backend's x25519 key), POSTs it to
//     `<base>/oxen/v4/lsrpc`, and decrypts the reply with `onionreq::ResponseParser`. This is
//     onion-request mode. (The stable backport uses only this transport.)
//
// Both move bytes with libcurl. The onion path does not build a real multi-hop route (that is a
// separate, stable protocol tested elsewhere) -- only the final destination-encrypted layer, which
// is exactly what `/oxen/v4/lsrpc` decrypts.
// ---------------------------------------------------------------------------

// A transport delivers a request (endpoint + content_type + opaque body) to the backend and returns
// the response body. `content_type` is what libsession's *_request() builders emit; clients must
// relay it verbatim (libsession owns the wire encoding and it may change).
using PostFn = std::function<std::string(
        std::string_view endpoint, std::string_view content_type, std::string_view body)>;

// Drive a transport straight from a built ProRequest.
static std::string send(const PostFn& transport, const ProRequest& r) {
    return transport(r.endpoint, r.content_type, r.data);
}

// Split e.g. "http://127.0.0.1:5000" into protocol / host / port.
struct ParsedBackendUrl {
    std::string protocol;
    std::string host;
    uint16_t port;
};
static ParsedBackendUrl parse_backend_url(std::string_view url) {
    ParsedBackendUrl r;
    auto pos = url.find("://");
    r.protocol = pos == std::string_view::npos ? "http" : std::string{url.substr(0, pos)};
    std::string_view rest = pos == std::string_view::npos ? url : url.substr(pos + 3);
    if (auto slash = rest.find('/'); slash != std::string_view::npos)
        rest = rest.substr(0, slash);
    if (auto colon = rest.find(':'); colon != std::string_view::npos) {
        r.host = std::string{rest.substr(0, colon)};
        r.port = static_cast<uint16_t>(std::stoi(std::string{rest.substr(colon + 1)}));
    } else {
        r.host = std::string{rest};
        r.port = r.protocol == "https" ? 443 : 80;
    }
    return r;
}

static std::string join_url(std::string_view base, std::string_view path) {
    std::string url{base};
    if (!url.empty() && url.back() == '/')
        url.pop_back();
    if (!path.empty() && path.front() != '/')
        url += '/';
    url += path;
    return url;
}

// Plain HTTP POST to `<base>/<endpoint>` (session-router tunnel mode), relaying content_type.
static PostFn make_direct_http_transport(CURL* curl, std::string base_url) {
    return [curl, base_url = std::move(base_url)](
                   std::string_view endpoint,
                   std::string_view content_type,
                   std::string_view body) {
        curl_slist* headers =
                curl_slist_append(nullptr, ("Content-Type: " + std::string{content_type}).c_str());
        scope_exit free_headers{[&]() { curl_slist_free_all(headers); }};
        return curl_do_basic_blocking_post_request(
                curl, headers, join_url(base_url, endpoint), body);
    };
}

// Innermost v4 onion piece to `<base>/oxen/v4/lsrpc` (onion-request mode). `backend_ed25519_pubkey`
// is the backend's signing pubkey (fetched from /status); its x25519 form is the destination key.
static PostFn make_onion_v4_transport(
        CURL* curl, std::string base_url, std::span<const uint8_t, 32> backend_ed25519_pubkey) {
    using namespace session::network;
    using namespace session::onionreq;

    auto parts = parse_backend_url(base_url);
    x25519_pubkey backend_x25519 = compute_x25519_pubkey(backend_ed25519_pubkey);

    return [curl, base_url = std::move(base_url), parts, backend_x25519](
                   std::string_view endpoint,
                   std::string_view content_type,
                   std::string_view body) {
        // Relay content_type as the inner (proxied) request's Content-Type.
        std::vector<std::pair<std::string, std::string>> inner_headers{
                {"Content-Type", std::string{content_type}}};
        ServerDestination dest{
                parts.protocol,
                parts.host,
                backend_x25519,
                parts.port,
                std::move(inner_headers),
                "POST"};

        Builder builder{
                network_destination{dest},
                std::string{endpoint},
                /*nodes=*/{},
                EncryptType::xchacha20};

        std::vector<unsigned char> body_bytes{
                reinterpret_cast<const unsigned char*>(body.data()),
                reinterpret_cast<const unsigned char*>(body.data()) + body.size()};
        std::vector<unsigned char> blob = builder.generate_onion_blob(std::move(body_bytes));

        // The lsrpc body is the raw encrypted onion blob; post it as opaque bytes. (An unheadered
        // curl POST defaults to application/x-www-form-urlencoded, which makes Werkzeug consume the
        // body into request.form and leaves request.data empty -> the backend 400s.)
        curl_slist* octet_headers =
                curl_slist_append(nullptr, "Content-Type: application/octet-stream");
        scope_exit octet_free{[&]() { curl_slist_free_all(octet_headers); }};

        std::string encrypted_response = curl_do_basic_blocking_post_request(
                curl,
                octet_headers,
                join_url(base_url, "/oxen/v4/lsrpc"),
                std::string_view{reinterpret_cast<const char*>(blob.data()), blob.size()});

        // ResponseParser reuses the builder's saved ephemeral keypair to decrypt the reply.
        ResponseParser parser{builder};
        DecryptedResponse resp = parser.decrypted_response(encrypted_response);
        return resp.body.value_or(std::string{});
    };
}

// Live-backend tests (tag [pro_live]), run against an ephemeral dev backend stood up by
// tests/pro_backend/run-dev-backend.sh: they drive the C++ API over the real request path against a
// real backend (redemption via provider_dry_run + a DB-seeded witnessed payment). This first case
// validates the infrastructure + both transports end-to-end via /status.
TEST_CASE("Pro backend live /status round-trip", "[pro_backend][pro_live]") {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    scope_exit curl_cleanup{[&]() { curl_global_cleanup(); }};
    CURL* curl = curl_easy_init();
    REQUIRE(curl);
    scope_exit curl_free{[&]() { curl_easy_cleanup(curl); }};

    const std::string& base_url = g_test_pro_backend_dev_server_url;

    // Parse the /status success envelope and return the signing pubkey (hex).
    auto status_pubkey_hex = [](std::string_view response_json) -> std::string {
        INFO("/status response: " << response_json);
        auto j = nlohmann::json::parse(response_json);
        REQUIRE(j.at("status").get<std::string>() == "ok");
        const auto& result = j.at("result");
        CHECK(result.contains("version"));
        CHECK(result.contains("timestamp"));
        auto pubkey = result.at("signing_pubkey").get<std::string>();
        REQUIRE(pubkey.size() == 64);
        REQUIRE(oxenc::is_hex(pubkey));
        return pubkey;
    };

    // 1) Fetch /status over the direct (session-router-style) HTTP transport.
    PostFn direct = make_direct_http_transport(curl, base_url);
    std::string direct_pubkey = status_pubkey_hex(direct("status", "application/json", ""));

    // 2) Build the onion transport from the pubkey we just fetched, then re-fetch /status over it:
    //    this exercises the full v4 onion encrypt/decrypt round-trip against the real backend.
    auto pubkey_bytes = oxenc::from_hex(direct_pubkey);
    REQUIRE(pubkey_bytes.size() == 32);
    std::array<uint8_t, 32> ed_pubkey{};
    std::memcpy(ed_pubkey.data(), pubkey_bytes.data(), ed_pubkey.size());

    PostFn onion = make_onion_v4_transport(curl, base_url, ed_pubkey);
    std::string onion_pubkey = status_pubkey_hex(onion("status", "application/json", ""));

    // Both transports must report the same signing key.
    CHECK(onion_pubkey == direct_pubkey);
}

// Shell out to the python seeding helper (tests/pro_backend/seed_payment.py) to inject backend DB
// state (a witnessed-unredeemed payment, or a revocation) directly. The launcher exports
// PRO_SEED_PYTHON / PRO_SEED_SCRIPT / PRO_BACKEND_DIR and the shared SESH_PRO_BACKEND_DB_URL. Args
// are test-controlled, so the naive single-quote wrapping is sufficient.
static void run_seed_helper(const std::vector<std::string>& args) {
    const char* py = std::getenv("PRO_SEED_PYTHON");
    const char* script = std::getenv("PRO_SEED_SCRIPT");
    REQUIRE(py != nullptr);
    REQUIRE(script != nullptr);
    std::string cmd = std::string(py) + " " + script;
    for (const auto& a : args)
        cmd += " '" + a + "'";
    INFO("seed: " << cmd);
    REQUIRE(std::system(cmd.c_str()) == 0);
}

static std::array<uint8_t, 32> fetch_backend_pubkey(const PostFn& transport) {
    auto j = nlohmann::json::parse(transport("status", "application/json", ""));
    REQUIRE(j.at("status").get<std::string>() == "ok");
    auto hex = j.at("result").at("signing_pubkey").get<std::string>();
    auto bytes = oxenc::from_hex(hex);
    REQUIRE(bytes.size() == 32);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), bytes.data(), out.size());
    return out;
}

// The core wire-contract flow: build *real* requests with the C++ API, send them over onion to a
// backend that redeems a witnessed (seeded) payment, and check every response parses + the issued
// proofs verify against the backend's signing key. Any signed-message drift on either side (field
// order, integer encoding, `\0` framing, domain prefix -- the scheme signs the message bytes
// directly, no hash) or a renamed JSON key breaks this. Runs the whole flow once per provider via
// SECTIONs: google_play exercises the composite "token|order_id" payment_id, app_store the plain tx
// id. Each SECTION uses fresh keys + a freshly-seeded payment, so the runs are independent on the
// shared ephemeral backend.
TEST_CASE("Pro backend live full flow", "[pro_backend][pro_live]") {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    scope_exit curl_cleanup{[&]() { curl_global_cleanup(); }};
    CURL* curl = curl_easy_init();
    REQUIRE(curl);
    scope_exit curl_free{[&]() { curl_easy_cleanup(curl); }};

    const std::string& base_url = g_test_pro_backend_dev_server_url;
    PostFn direct = make_direct_http_transport(curl, base_url);
    std::array<uint8_t, 32> backend_pubkey = fetch_backend_pubkey(direct);
    PostFn onion = make_onion_v4_transport(curl, base_url, backend_pubkey);

    // Provider under test; the whole flow below re-runs once per SECTION.
    std::string provider;
    SECTION("google_play") {
        provider = SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY;
    }
    SECTION("app_store") {
        provider = SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_APP_STORE;
    }
    INFO("provider=" << provider);

    // Fresh account keys.
    std::array<unsigned char, 32> master_pk{}, rotating_pk{};
    std::array<unsigned char, 64> master_sk{}, rotating_sk{};
    crypto_sign_ed25519_keypair(master_pk.data(), master_sk.data());
    crypto_sign_ed25519_keypair(rotating_pk.data(), rotating_sk.data());
    std::string master_hex = oxenc::to_hex(master_pk);

    // Opaque per-provider payment_id: google is the composite "<token>|<order_id>" (backend splits
    // on the first '|'); app_store is a bare transaction id.
    std::string payment_id = provider == SESSION_PRO_BACKEND_PAYMENT_PROVIDER_CODE_GOOGLE_PLAY
                                   ? master_hex.substr(0, 16) + "|GPA." + master_hex.substr(16, 12)
                                   : "20000000" + master_hex.substr(0, 10);

    // Seed the witnessed-unredeemed payment; a subsequent master-signed request (generate_pro_proof
    // below) binds/redeems it implicitly -- there is no client-submitted add-payment step.
    run_seed_helper(
            {"payment",
             "--provider",
             provider,
             "--payment-id",
             payment_id,
             "--master-pubkey",
             master_hex,
             "--plan",
             "1m"});

    auto now = session::sysclock_now_s();

    // 1) generate_pro_proof: redemption is implicit, so this master-signed request binds the seeded
    //    payment before answering and returns a signed proof for the paired rotating key.
    ProRequest gen_req = pro_proof_request(master_sk, rotating_sk, now);
    GenerateProProofResponse gen = parse_pro_proof(send(onion, gen_req));
    INFO("generate_pro_proof " << gen.error.value_or(""));
    REQUIRE(gen.status == ResponseStatus::Ok);
    CHECK(gen.proof.verify_signature(backend_pubkey));
    CHECK(std::memcmp(gen.proof.rotating_pubkey.data(), rotating_pk.data(), 32) == 0);

    // 1b) generate_pro_proof again with a NEW rotating key -> a fresh proof for the same
    //     subscription, so it shares the first proof's revocation_tag (same subscription epoch).
    std::array<unsigned char, 32> rotating2_pk{};
    std::array<unsigned char, 64> rotating2_sk{};
    crypto_sign_ed25519_keypair(rotating2_pk.data(), rotating2_sk.data());
    ProRequest gen2_req = pro_proof_request(master_sk, rotating2_sk, now);
    GenerateProProofResponse gen2 = parse_pro_proof(send(onion, gen2_req));
    INFO("generate_pro_proof(2) " << gen2.error.value_or(""));
    REQUIRE(gen2.status == ResponseStatus::Ok);
    CHECK(gen2.proof.verify_signature(backend_pubkey));
    CHECK(std::memcmp(gen2.proof.rotating_pubkey.data(), rotating2_pk.data(), 32) == 0);
    CHECK(gen2.proof.revocation_tag == gen.proof.revocation_tag);

    // 2) get_pro_status: account ACTIVE and the single latest payment is our redeemed one.
    ProStatusResponse status = parse_pro_status(send(onion, pro_status_request(master_sk, now)));
    INFO("get_pro_status " << status.error.value_or(""));
    REQUIRE(status.status == ResponseStatus::Ok);
    CHECK(status.user_status == "active");
    REQUIRE(status.latest_payment.has_value());
    CHECK(status.latest_payment->payment_id == payment_id);
    CHECK(status.latest_payment->payment_provider == provider);
    // plan is the parsed billing period (§1): "1m" -> {count 1, month}.
    CHECK(status.latest_payment->plan.count == 1);
    CHECK(status.latest_payment->plan.unit == ProPlanUnit::month);
    CHECK(status.latest_payment->status == "redeemed");

    // 2b) get_payment_details: newest page (empty cursor) carries our payment. This
    //     master has exactly one payment, so it fits in one page and next_cursor is empty.
    PaymentDetailsResponse det =
            parse_payment_details(send(onion, payment_details_request(master_sk, now, 10, "")));
    INFO("get_payment_details " << det.error.value_or(""));
    REQUIRE(det.status == ResponseStatus::Ok);
    CHECK(det.payments_total >= 1);
    CHECK(det.items.size() >= 1);
    CHECK_FALSE(det.next_cursor.has_value());  // limit 10 >= 1 payment -> no further page
    bool found = false;
    for (const auto& item : det.items) {
        if (item.payment_id == payment_id) {
            found = true;
            CHECK(item.payment_provider == provider);
            CHECK(item.plan.count == 1);
            CHECK(item.plan.unit == ProPlanUnit::month);
            CHECK(item.status == "redeemed");
        }
    }
    CHECK(found);

    // 3) get_payment_details pagination + opaque-cursor round-trip: a limit-1 page returns one item
    //    and (being a full page) a next_cursor; re-requesting with that cursor echoed back verbatim
    //    must be accepted and return the next page. With a single payment on this master, page 2 is
    //    empty and terminates (next_cursor cleared). This is the real test of the opaque keyset
    //    cursor -- a tampered/synthesized cursor would be rejected, so a clean round-trip proves
    //    the client relayed it faithfully.
    PaymentDetailsResponse page1 =
            parse_payment_details(send(onion, payment_details_request(master_sk, now, 1, "")));
    REQUIRE(page1.status == ResponseStatus::Ok);
    CHECK(page1.items.size() == 1);
    if (det.payments_total == 1) {
        REQUIRE(page1.next_cursor.has_value());  // a full page yields a cursor to try next
        PaymentDetailsResponse page2 = parse_payment_details(
                send(onion, payment_details_request(master_sk, now, 1, *page1.next_cursor)));
        REQUIRE(page2.status ==
                ResponseStatus::Ok);  // the opaque cursor was accepted (echo round-trip)
        CHECK(page2.items.empty());   // no more payments
        CHECK_FALSE(page2.next_cursor.has_value());  // end of data
    }
}

// Revocation-list round-trip: seed + redeem a payment, seed a revocation for that generation, then
// confirm get_pro_revocations surfaces it and its tag matches the issued proof. Kept independent of
// the lifecycle flow so the revocation doesn't perturb those assertions.
TEST_CASE("Pro backend live get_pro_revocations", "[pro_backend][pro_live]") {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    scope_exit curl_cleanup{[&]() { curl_global_cleanup(); }};
    CURL* curl = curl_easy_init();
    REQUIRE(curl);
    scope_exit curl_free{[&]() { curl_easy_cleanup(curl); }};

    const std::string& base_url = g_test_pro_backend_dev_server_url;
    PostFn direct = make_direct_http_transport(curl, base_url);
    std::array<uint8_t, 32> backend_pubkey = fetch_backend_pubkey(direct);
    PostFn onion = make_onion_v4_transport(curl, base_url, backend_pubkey);

    std::array<unsigned char, 32> master_pk{}, rotating_pk{};
    std::array<unsigned char, 64> master_sk{}, rotating_sk{};
    crypto_sign_ed25519_keypair(master_pk.data(), master_sk.data());
    crypto_sign_ed25519_keypair(rotating_pk.data(), rotating_sk.data());
    std::string master_hex = oxenc::to_hex(master_pk);

    // Seed + redeem an app_store payment so the master has an active generation to revoke.
    std::string payment_id = "20000000" + master_hex.substr(0, 10);
    run_seed_helper(
            {"payment",
             "--provider",
             "app_store",
             "--payment-id",
             payment_id,
             "--master-pubkey",
             master_hex,
             "--plan",
             "1m"});
    // Bind + redeem it implicitly (any master-signed request binds unbound payments) and get a
    // proof to revoke.
    ProRequest gen_req = pro_proof_request(master_sk, rotating_sk, session::sysclock_now_s());
    GenerateProProofResponse gen = parse_pro_proof(send(onion, gen_req));
    INFO("generate_pro_proof " << gen.error.value_or(""));
    REQUIRE(gen.status == ResponseStatus::Ok);
    CHECK(gen.status == ResponseStatus::Ok);

    // Revoke that payment's generation (revocation is terminal now -- revoked_at set once, no
    // per-entry expiry), then poll: the list must carry our proof's revocation_tag.
    run_seed_helper({"revoke", "--provider", "app_store", "--payment-id", payment_id});

    ProRequest rev_req = revocations_request(0);
    GetProRevocationsResponse rev = parse_revocations(send(onion, rev_req));
    INFO("get_pro_revocations" << rev.error.value_or(""));
    REQUIRE(rev.status == ResponseStatus::Ok);
    CHECK(rev.retain_for.count() > 0);
    CHECK_FALSE(rev.items.empty());
    bool found = false;
    for (const auto& it : rev.items)
        if (it.revocation_tag == gen.proof.revocation_tag)
            found = true;
    CHECK(found);
}
#endif
