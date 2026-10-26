#include <SessionProtos.pb.h>

#include <catch2/catch_test_macros.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/util.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;
using namespace std::literals;
using namespace oxenc::literals;

namespace {

// Returns the session_id of a Core as a std::byte array.
std::array<std::byte, 33> sid_bytes(Core& c) {
    std::array<std::byte, 33> result;
    auto sid = c.globals.session_id();
    std::memcpy(result.data(), sid.data(), 33);
    return result;
}

// Minimal valid SessionProtos::Content protobuf: field 15 (sigTimestamp) = 1.
constexpr auto MINIMAL_CONTENT = "7801"_hex_b;

// A valid session ID for tests that don't need actual decryption on the other side.
constexpr auto DUMMY_SID =
        "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

std::span<const std::byte> content_bytes() {
    static const auto bytes = std::as_bytes(std::span{MINIMAL_CONTENT});
    return bytes;
}

}  // namespace

// ── V2 PFS send + receive round-trip ────────────────────────────────────────────────────────────

TEST_CASE("send_dm: v2 PFS round-trip", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<MessageSendStatus> statuses;
    std::vector<std::optional<MessageEncryption>> encryptions;

    callbacks sender_cbs;
    sender_cbs.message_send_status =
            [&](int64_t, MessageSendStatus s, auto, std::optional<MessageEncryption> e) {
                statuses.push_back(s);
                encryptions.push_back(e);
            };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};
    auto* net = attach_mock_network(*sender);

    recipient->devices.active_account_keys();
    auto [x25519_pub, mlkem_pub] = TestHelper::active_account_pubkeys(*recipient);
    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_cache(*sender, recip_sid, x25519_pub, mlkem_pub);

    auto msg_id = sender->send_dm(recip_sid, content_bytes(), clock_now_ms());
    CHECK(msg_id == 1);

    auto sent = stores(*net);
    REQUIRE(sent.size() == 1);
    CHECK(store_body(*sent[0])["namespace"] == static_cast<int16_t>(config::Namespace::Default));
    auto payload = store_payload(*sent[0]);
    REQUIRE(accept_stores(*net) == 1);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::success);
    // What it was encrypted with, reported once decided and again on success.
    CHECK(encryptions == std::vector<std::optional<MessageEncryption>>{
                                 MessageEncryption::v2_pfs, MessageEncryption::v2_pfs});

    // What went onto the wire, fed back in as the recipient's swarm would deliver it.
    SwarmMessage sm;
    sm.data = payload;
    sm.hash = "send_test_hash";
    sm.timestamp = clock_now_ms();
    sm.expiry = clock_now_ms() + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    CHECK(received[0].encryption == MessageEncryption::v2_pfs);
    CHECK(std::ranges::equal(received[0].content, MINIMAL_CONTENT));
}

// ── V1 fallback (NAK, force_v2=false) ───────────────────────────────────────────────────────────

TEST_CASE("send_dm: v1 fallback on NAK", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<MessageSendStatus> statuses;

    callbacks sender_cbs;
    sender_cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};
    auto* net = attach_mock_network(*sender);

    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_nak(*sender, recip_sid);

    sender->send_dm(recip_sid, content_bytes(), clock_now_ms());

    auto sent = stores(*net);
    REQUIRE(sent.size() == 1);
    auto payload = store_payload(*sent[0]);
    REQUIRE(accept_stores(*net) == 1);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::success);

    SwarmMessage sm;
    sm.data = payload;
    sm.hash = "v1_hash";
    sm.timestamp = clock_now_ms();
    sm.expiry = clock_now_ms() + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    CHECK(received[0].encryption == MessageEncryption::v1);
}

// ── V2 non-PFS (force_v2=true, NAK) ────────────────────────────────────────────────────────────

TEST_CASE("send_dm: v2 non-PFS with force_v2", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;
    std::vector<MessageSendStatus> statuses;

    callbacks sender_cbs;
    sender_cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{sender_cbs};
    TempCore recipient{recip_cbs};
    auto* net = attach_mock_network(*sender);

    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_nak(*sender, recip_sid);

    sender->send_dm(
            recip_sid, content_bytes(), clock_now_ms(), std::nullopt, 14 * 24h, /*force_v2=*/true);

    auto sent = stores(*net);
    REQUIRE(sent.size() == 1);
    auto payload = store_payload(*sent[0]);
    REQUIRE(accept_stores(*net) == 1);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::success);

    SwarmMessage sm;
    sm.data = payload;
    sm.hash = "nopfs_hash";
    sm.timestamp = clock_now_ms();
    sm.expiry = clock_now_ms() + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    CHECK(received[0].encryption == MessageEncryption::v2_basic);
}

// ── No network error ────────────────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: no_network once the keys are known but nothing can send", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };

    TempCore sender{cbs};
    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::no_network);
}

// ── No network, no cache → immediate no_network ────────────────────────────────────────────────

TEST_CASE("send_dm: no_network when no cache and no network", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };

    TempCore sender{cbs};

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    // No cache entry and no network → immediate no_network.
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0] == MessageSendStatus::no_network);
}

// ── The store request a send produces ───────────────────────────────────────────────────────────

TEST_CASE("send_dm: the store names the recipient, namespace and ttl", "[core][send_dm]") {
    TempCore sender{};
    auto* net = attach_mock_network(*sender);

    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    auto custom_ttl = std::chrono::milliseconds{7 * 24h};
    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms(), std::nullopt, custom_ttl);

    auto sent = stores(*net);
    REQUIRE(sent.size() == 1);
    auto body = store_body(*sent[0]);
    CHECK(body["pubkey"] == oxenc::to_hex(DUMMY_SID));
    CHECK(body["namespace"] == static_cast<int16_t>(config::Namespace::Default));
    CHECK(body["ttl"] == custom_ttl.count());
}

// ── Network error status ────────────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: network_error when store fails", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };

    TempCore sender{cbs};
    auto* net = attach_mock_network(*sender);

    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());
    REQUIRE(answer_stores(*net, false) == 1);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == MessageSendStatus::sending);
    CHECK(statuses[1] == MessageSendStatus::network_error);
}

// ── Monotonic message IDs ───────────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: message IDs are monotonically increasing", "[core][send_dm]") {
    TempCore sender{};
    auto* net = attach_mock_network(*sender);

    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    auto id1 = sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());
    auto id2 = sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());
    auto id3 = sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    CHECK(id1 == 1);
    CHECK(id2 == 2);
    CHECK(id3 == 3);
}

// ── Success is the swarm's answer, not the dispatch ─────────────────────────────────────────────

TEST_CASE("send_dm: success waits for the store to be answered", "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };

    TempCore sender{cbs};
    auto* net = attach_mock_network(*sender);

    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    // `sending` means dispatched, and stops there: nothing has come back from the swarm yet.
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0] == MessageSendStatus::sending);
    REQUIRE(stores(*net).size() == 1);

    REQUIRE(accept_stores(*net) == 1);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[1] == MessageSendStatus::success);
}

// ── Content protobuf overload ───────────────────────────────────────────────────────────────────

TEST_CASE("send_dm: Content overload round-trip", "[core][send_dm]") {
    std::vector<ReceivedMessage> received;

    callbacks recip_cbs;
    recip_cbs.message_received = [&](ReceivedMessage&& m) { received.push_back(std::move(m)); };

    TempCore sender{};
    TempCore recipient{recip_cbs};
    auto* net = attach_mock_network(*sender);

    recipient->devices.active_account_keys();
    auto [x25519_pub, mlkem_pub] = TestHelper::active_account_pubkeys(*recipient);
    auto recip_sid = sid_bytes(*recipient);
    TestHelper::seed_pfs_cache(*sender, recip_sid, x25519_pub, mlkem_pub);

    auto ts = clock_now_ms();
    SessionProtos::Content content;
    content.mutable_datamessage()->set_body("hello from the Content overload");

    sender->send_dm(recip_sid, content, ts);

    auto sent = stores(*net);
    REQUIRE(sent.size() == 1);
    auto payload = store_payload(*sent[0]);

    SwarmMessage sm;
    sm.data = payload;
    sm.hash = "content_overload_hash";
    sm.timestamp = ts;
    sm.expiry = ts + 24h;

    recipient->receive_messages({&sm, 1}, config::Namespace::Default, true);

    REQUIRE(received.size() == 1);
    SessionProtos::Content decoded;
    REQUIRE(decoded.ParseFromArray(
            received[0].content.data(), static_cast<int>(received[0].content.size())));
    CHECK(decoded.datamessage().body() == "hello from the Content overload");

    // An unset sigTimestamp is filled in from sent_timestamp.
    CHECK(decoded.sigtimestamp() == static_cast<uint64_t>(ts.time_since_epoch().count()));
}

TEST_CASE("send_dm: Content overload preserves a matching sigTimestamp", "[core][send_dm]") {
    TempCore sender{};
    auto* net = attach_mock_network(*sender);

    TestHelper::seed_pfs_nak(*sender, DUMMY_SID);

    auto ts = clock_now_ms();
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    content.mutable_datamessage()->set_body("explicit timestamp");

    CHECK_NOTHROW(sender->send_dm(DUMMY_SID, content, ts));
    CHECK(stores(*net).size() == 1);
}

TEST_CASE("send_dm: Content overload rejects a mismatched sigTimestamp", "[core][send_dm]") {
    TempCore sender{};

    auto ts = clock_now_ms();
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()) + 5000);
    content.mutable_datamessage()->set_body("mismatched");

    CHECK_THROWS_AS(sender->send_dm(DUMMY_SID, content, ts), std::invalid_argument);
}

// ── Sends queued behind a PFS key fetch ─────────────────────────────────────────────────────────

TEST_CASE(
        "send_dm: a send queued behind a key fetch is released when the fetch settles",
        "[core][send_dm]") {
    std::vector<MessageSendStatus> statuses;
    std::vector<PfsKeyFetch> fetches;

    callbacks cbs;
    cbs.message_send_status = [&](int64_t, MessageSendStatus s, auto, auto) {
        statuses.push_back(s);
    };
    cbs.pfs_keys_fetched = [&](std::span<const std::byte, 33>, PfsKeyFetch r) {
        fetches.push_back(r);
    };

    TempCore sender{cbs};
    auto* net = attach_mock_network(*sender);

    // Nothing cached for this recipient, so the send is queued behind a key fetch.
    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0] == MessageSendStatus::awaiting_keys);
    CHECK(stores(*net).empty());
    REQUIRE(net->sent_requests.size() == 1);
    CHECK(net->sent_requests[0].request.endpoint == "retrieve");

    // A failed fetch holds it, with no key to fall back on, until a retry settles it.
    REQUIRE(fail_retrieves(*net) == 1);
    CHECK(stores(*net).empty());
    CHECK(statuses.back() == MessageSendStatus::retrying);

    TestHelper::fire_pfs_retry(*sender, DUMMY_SID);
    REQUIRE(answer_retrieves(*net) == 1);

    CHECK(fetches == std::vector{PfsKeyFetch::failed, PfsKeyFetch::not_found});
    REQUIRE(accept_stores(*net) == 1);
    CHECK(statuses.back() == MessageSendStatus::success);
}

TEST_CASE(
        "send_dm: every send queued for one recipient is released by a single fetch",
        "[core][send_dm]") {
    std::vector<PfsKeyFetch> fetches;

    callbacks cbs;
    cbs.pfs_keys_fetched = [&](std::span<const std::byte, 33>, PfsKeyFetch r) {
        fetches.push_back(r);
    };

    TempCore sender{cbs};
    auto* net = attach_mock_network(*sender);

    for (int i = 0; i < 3; i++)
        sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());

    CHECK(stores(*net).empty());
    REQUIRE(!net->sent_requests.empty());

    // Settling one fetch drains the whole queue for that recipient, even though each send asked
    // for the keys in its own right.
    REQUIRE(answer_retrieves(*net, {}, 1) == 1);

    CHECK(stores(*net).size() == 3);
    CHECK(fetches.size() == 1);
}

TEST_CASE(
        "send_dm: a throwing pfs_keys_fetched callback does not strand queued sends",
        "[core][send_dm]") {
    callbacks cbs;
    // Callbacks are not permitted to throw, but a buggy one must not take the queued sends with
    // it: the flush happens regardless.
    cbs.pfs_keys_fetched = [](std::span<const std::byte, 33>, PfsKeyFetch) {
        throw std::runtime_error{"buggy application callback"};
    };

    TempCore sender{cbs};
    auto* net = attach_mock_network(*sender);

    sender->send_dm(DUMMY_SID, content_bytes(), clock_now_ms());
    REQUIRE(!net->sent_requests.empty());

    CHECK_NOTHROW(answer_retrieves(*net));
    CHECK(stores(*net).size() == 1);
}
