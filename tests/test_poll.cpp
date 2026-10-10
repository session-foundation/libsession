#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"

using namespace session;

// The batch _poll() sends is one subrequest per polled namespace, and results are matched to it by
// position.  Both helpers below therefore work from the *request*: which namespaces it asked for,
// and in what order.  That is what the real storage server does, and it means these tests do not
// have to be rewritten each time Core learns to poll another namespace -- a positional assertion
// breaks on every such change and says nothing about why.

// The parameters of the subrequest asking for `ns`.
// Note each of these binds the parsed json to a local before iterating it: ranging directly over
// `parse_json(body)["requests"]` takes a reference *into* a temporary that dies before the loop
// body runs, which reads as an empty batch rather than as an error.
static nlohmann::json params_for(std::span<const std::byte> request_body, int16_t ns) {
    auto batch = parse_json(request_body);
    for (const auto& r : batch["requests"])
        if (r["params"]["namespace"] == ns)
            return r["params"];
    throw std::runtime_error{"batch contains no subrequest for namespace {}"_format(ns)};
}

// The namespaces a batch asked for, sorted, for asserting the whole set at once.
static std::vector<int16_t> namespaces_in(std::span<const std::byte> request_body) {
    auto batch = parse_json(request_body);
    std::vector<int16_t> out;
    for (const auto& r : batch["requests"])
        out.push_back(r["params"]["namespace"].get<int16_t>());
    std::ranges::sort(out);
    return out;
}

// A batch response shaped to the request: one result per subrequest, carrying a single message in
// the one that asked for `ns` and nothing in the rest.
static nlohmann::json make_response(
        std::span<const std::byte> request_body,
        int16_t ns,
        std::vector<std::byte> msg_data,
        std::string hash) {
    auto batch = parse_json(request_body);
    auto results = nlohmann::json::array();
    for (const auto& r : batch["requests"]) {
        nlohmann::json body;
        body["messages"] = nlohmann::json::array();
        if (r["params"]["namespace"] == ns) {
            nlohmann::json item;
            item["data"] = oxenc::to_base64(msg_data);
            item["hash"] = hash;
            // A storage server always says when it will drop a message, and a link request takes
            // that as its deadline -- without one it would arrive already expired.
            item["expiry"] = epoch_ms(clock_now_ms() + 10min);
            body["messages"].push_back(std::move(item));
        }
        results.push_back({{"code", 200}, {"body", std::move(body)}});
    }
    return nlohmann::json{{"results", std::move(results)}};
}

TEST_CASE("Core automatic polling", "[core][poll]") {
    DeviceEventsRecorder events;
    core::callbacks cbs;
    cbs.devices = &events;

    TempCore core{cbs};
    auto* mock_net = attach_mock_network(*core);
    // Use a fixed non-zero pubkey for the node.
    mock_net->current_node.remote_pubkey[0] = std::byte{0x01};

    // Trigger poll via TestHelper
    TestHelper::poll(*core);

    REQUIRE(mock_net->sent_requests.size() == 1);
    auto& sent = mock_net->sent_requests[0];

    CHECK(sent.request.endpoint == "batch");
    auto& body = *sent.request.body;

    // Every namespace the account polls: the four user configs, one-to-one messages, and the two
    // the device group needs.
    CHECK(namespaces_in(body) == std::vector<int16_t>{-21, 0, 2, 3, 4, 5, 21});

    for (const auto& r : parse_json(body)["requests"])
        CHECK(r["method"] == "retrieve");

    // Devices (ns 21) requires auth, and is the namespace the rest of this test uses.
    auto params = params_for(body, 21);
    CHECK(params["pubkey"] == oxenc::to_hex(core->globals.session_id()));
    CHECK(params.contains("pubkey_ed25519"));
    CHECK(params.contains("timestamp"));
    CHECK(params.contains("signature"));
    // No prior hash for this node yet, so no last_hash in any subrequest.
    CHECK_FALSE(params.contains("last_hash"));

    // The config namespaces are owner-writable, so retrieving from them is signed too.
    CHECK(params_for(body, 2).contains("signature"));
    CHECK(params_for(body, 3).contains("signature"));

    // Default (ns 0) is signed; AccountPubkeys (ns -21) is public and is not.
    CHECK(params_for(body, 0).contains("signature"));
    CHECK_FALSE(params_for(body, -21).contains("signature"));

    // Build a valid link request from a second device sharing the same account seed.
    cleared_b32 seed_bytes;
    {
        auto seed_acc = core->globals.account_seed();
        std::ranges::copy(std::as_bytes(seed_acc.seed()), seed_bytes.begin());
    }
    TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
    auto outer_msg = TestHelper::build_link_request(*linker, *core).message;

    sent.callback(
            true, false, 200, {}, make_response(*sent.request.body, 21, outer_msg, "hash1").dump());
    TestHelper::drain(*core);

    // Verify last_hash was stored under this specific node's pubkey.
    CHECK(TestHelper::namespace_last_hash(*core, 21, mock_net->current_node.remote_pubkey) ==
          "hash1");
    CHECK(events.added.size() == 1);

    // Poll again with the same node — should include last_hash in the Devices subrequest.
    mock_net->sent_requests.clear();
    TestHelper::poll(*core);

    REQUIRE(mock_net->sent_requests.size() == 1);
    CHECK(params_for(*mock_net->sent_requests[0].request.body, 21)["last_hash"] == "hash1");
}

TEST_CASE(
        "Polling uses per-node last_hash to avoid missing messages on swarm-member switch",
        "[core][poll]") {
    TempCore c;
    auto* mock_net = attach_mock_network(*c);

    // Two distinct service nodes with different pubkeys.
    network::service_node node_a, node_b;
    node_a.remote_pubkey[0] = std::byte{0xAA};
    node_b.remote_pubkey[0] = std::byte{0xBB};

    // ── First poll: node A, no prior state ──────────────────────────────────────
    mock_net->current_node = node_a;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = params_for(*mock_net->sent_requests[0].request.body, 21);
        // No prior hash for any node — must not send last_hash.
        CHECK_FALSE(p.contains("last_hash"));
    }
    // Respond with hash "xyz" from node A.
    mock_net->sent_requests[0].callback(
            true,
            false,
            200,
            {},
            make_response(*mock_net->sent_requests[0].request.body, 21, {std::byte{0x01}}, "xyz")
                    .dump());
    TestHelper::drain(*c);
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_a.remote_pubkey) == "xyz");
    CHECK_FALSE(TestHelper::namespace_last_hash(*c, 21, node_b.remote_pubkey).has_value());

    // ── Second poll: still node A — must use A's stored hash ────────────────────
    mock_net->sent_requests.clear();
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = params_for(*mock_net->sent_requests[0].request.body, 21);
        CHECK(p["last_hash"] == "xyz");
    }

    // ── Third poll: switch to node B — no stored hash for B, so request everything ──
    mock_net->sent_requests.clear();
    mock_net->current_node = node_b;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = params_for(*mock_net->sent_requests[0].request.body, 21);
        // B has no recorded hash — must not send last_hash so we get everything.
        CHECK_FALSE(p.contains("last_hash"));
    }
    // Respond with hash "zyx" from node B (the message that B happens to have seen first).
    mock_net->sent_requests[0].callback(
            true,
            false,
            200,
            {},
            make_response(*mock_net->sent_requests[0].request.body, 21, {std::byte{0x02}}, "zyx")
                    .dump());
    TestHelper::drain(*c);
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_b.remote_pubkey) == "zyx");
    // A's hash is untouched.
    CHECK(TestHelper::namespace_last_hash(*c, 21, node_a.remote_pubkey) == "xyz");

    // ── Fourth poll: back to node A — must still use A's hash, not B's ──────────
    mock_net->sent_requests.clear();
    mock_net->current_node = node_a;
    TestHelper::poll(*c);
    REQUIRE(mock_net->sent_requests.size() == 1);
    {
        auto p = params_for(*mock_net->sent_requests[0].request.body, 21);
        CHECK(p["last_hash"] == "xyz");
    }
}

TEST_CASE("Poll: the sync cursor advances only after the batch is handled", "[core][poll]") {
    // Attached below, once there is a Core to own it; the callback that reads it does not run
    // until then either.
    MockNetwork* mock_net = nullptr;

    core::Core* core_ptr = nullptr;
    std::optional<std::string> hash_during_callback;
    bool called = false;

    // Observe the stored cursor from inside the handler.  If it has already advanced by the time
    // the batch is being handled, then a handler that fails -- or a crash at that moment -- loses
    // the batch permanently, because the swarm filters on last_hash.
    DeviceEventsRecorder events;
    events.on_added = [&](const core::device::LinkRequest&) {
        called = true;
        hash_during_callback = TestHelper::namespace_last_hash(
                *core_ptr, 21, mock_net->current_node.remote_pubkey);
    };
    core::callbacks cbs;
    cbs.devices = &events;

    TempCore core{cbs};
    core_ptr = &*core;
    mock_net = attach_mock_network(*core);
    mock_net->current_node.remote_pubkey[0] = std::byte{0x01};

    cleared_b32 seed_bytes;
    {
        auto seed_acc = core->globals.account_seed();
        std::ranges::copy(std::as_bytes(seed_acc.seed()), seed_bytes.begin());
    }
    TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
    auto outer_msg = TestHelper::build_link_request(*linker, *core).message;

    TestHelper::poll(*core);
    REQUIRE(mock_net->sent_requests.size() == 1);
    mock_net->sent_requests[0].callback(
            true,
            false,
            200,
            {},
            make_response(*mock_net->sent_requests[0].request.body, 21, outer_msg, "hash1").dump());
    TestHelper::drain(*core);

    REQUIRE(called);
    CHECK(!hash_during_callback);
    CHECK(TestHelper::namespace_last_hash(*core, 21, mock_net->current_node.remote_pubkey) ==
          "hash1");
}

// A batch response where every namespace answered successfully and returned nothing.
static nlohmann::json make_empty_response(std::span<const std::byte> request_body) {
    auto batch = parse_json(request_body);
    auto results = nlohmann::json::array();
    for (size_t i = 0; i < batch["requests"].size(); i++)
        results.push_back({{"code", 200}, {"body", {{"messages", nlohmann::json::array()}}}});
    return nlohmann::json{{"results", std::move(results)}};
}

// Marks the result for `ns` as having more behind it, found by the position its subrequest occupies
// -- which is how Core matches results to requests too.
static void set_more(
        nlohmann::json& response, std::span<const std::byte> request_body, int16_t ns) {
    auto batch = parse_json(request_body);
    for (size_t i = 0; i < batch["requests"].size(); i++)
        if (batch["requests"][i]["params"]["namespace"] == ns)
            response["results"][i]["body"]["more"] = true;
}

TEST_CASE("Poll: a truncated namespace is continued before it is reported final", "[core][poll]") {
    DeviceEventsRecorder events;
    core::callbacks cbs;
    cbs.devices = &events;

    TempCore core{cbs};
    auto* mock_net = attach_mock_network(*core);
    mock_net->current_node.remote_pubkey[0] = std::byte{0x01};

    cleared_b32 seed_bytes;
    {
        auto seed_acc = core->globals.account_seed();
        std::ranges::copy(std::as_bytes(seed_acc.seed()), seed_bytes.begin());
    }
    TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
    auto outer_msg = TestHelper::build_link_request(*linker, *core).message;

    TestHelper::poll(*core);
    REQUIRE(mock_net->sent_requests.size() == 1);

    auto first = *mock_net->sent_requests[0].request.body;
    auto resp = make_response(first, 21, outer_msg, "hash1");
    set_more(resp, first, 21);

    // Copied out before invoking: handling the response appends to `sent_requests` -- the batch is
    // not final, so a continuation goes out -- which can reallocate the vector the callback itself
    // lives in.
    auto reply = mock_net->sent_requests[0].callback;
    reply(true, false, 200, {}, resp.dump());
    TestHelper::drain(*core);

    // The request is stored, but the batch was not final, so nothing has been reported yet.
    CHECK(events.added.empty());

    auto sent = polls(*mock_net);
    REQUIRE(sent.size() == 2);
    auto second = *sent[1]->request.body;
    CHECK(namespaces_in(second) == std::vector<int16_t>{21});
    CHECK(params_for(second, 21)["last_hash"] == "hash1");

    // Nothing left behind it: an empty answer is still an answer, and is what makes the batch
    // final.
    auto reply2 = sent[1]->callback;
    reply2(true, false, 200, {}, make_empty_response(second).dump());
    TestHelper::drain(*core);

    CHECK(events.added.size() == 1);
}

TEST_CASE("Poll: `more` with nothing returned does not continue", "[core][poll]") {
    TempCore core;
    auto* mock_net = attach_mock_network(*core);

    TestHelper::poll(*core);
    REQUIRE(mock_net->sent_requests.size() == 1);

    auto first = *mock_net->sent_requests[0].request.body;
    auto resp = make_empty_response(first);
    set_more(resp, first, 21);

    auto reply = mock_net->sent_requests[0].callback;
    reply(true, false, 200, {}, resp.dump());
    TestHelper::drain(*core);

    // There is no new hash to move the cursor to, so another round would ask the same question.
    // Counting polls rather than requests: a completed fetch also pushes whatever the group owes,
    // which a fresh account always does.
    CHECK(polls(*mock_net).size() == 1);
}

// Answers the poll for namespace 21 with nothing, which is what makes the fetch final and is what
// the group push hangs off.
static void finish_poll(core::Core& core, MockNetwork& net) {
    auto p = polls(net);
    REQUIRE(!p.empty());
    auto& last = *p.back();
    auto body = *last.request.body;
    auto reply = last.callback;
    reply(true, false, 200, {}, make_empty_response(body).dump());
    TestHelper::drain(core);
}

TEST_CASE(
        "Devices: a completed fetch pushes the group, and the next push replaces it",
        "[core][poll][devices]") {
    TempCore core;
    auto* mock_net = attach_mock_network(*core);

    // A generated account registers itself and mints its first account key seed, so a push is owed
    // from the start and nothing has to dirty it first.
    TestHelper::poll(*core);
    finish_poll(*core, *mock_net);

    auto sent = pushes(*mock_net);
    REQUIRE(sent.size() == 1);
    auto reqs = push_requests(*sent[0]);

    // One store and no delete: there is no earlier message of ours to replace yet.
    REQUIRE(reqs.size() == 1);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[0]["params"]["namespace"] == 21);
    CHECK(reqs[0]["params"]["ttl"] ==
          std::chrono::milliseconds{core::Devices::DEVICE_GROUP_TTL}.count());

    auto confirm = sent[0]->callback;
    confirm(true,
            false,
            200,
            {},
            nlohmann::json{{"results", {{{"code", 200}, {"body", {{"hash", "group1"}}}}}}}.dump());
    TestHelper::drain(*core);

    // Confirmed, so nothing is owed and a second fetch pushes nothing.
    TestHelper::poll(*core);
    finish_poll(*core, *mock_net);
    CHECK(pushes(*mock_net).size() == 1);

    // Dirty it again: our own record changed, so the group has something new to say.
    core::device::Info info{};
    info.type = core::device::Type::Session_CLI;
    info.description = "a second thing to say";
    core->devices.update_info(info, await);

    TestHelper::poll(*core);
    finish_poll(*core, *mock_net);

    sent = pushes(*mock_net);
    REQUIRE(sent.size() == 2);
    reqs = push_requests(*sent[1]);

    // The store, then a delete naming what the first push left in the swarm.  Namespace 21 keeps
    // every message, so without this the old one sits there for its whole TTL.
    REQUIRE(reqs.size() == 2);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[1]["method"] == "delete");
    CHECK(reqs[1]["params"]["messages"] == nlohmann::json::array({"group1"}));
}

TEST_CASE(
        "Devices: a push obsoletes what it merged, not only what it wrote",
        "[core][poll][devices]") {
    TempCore core;
    auto* mock_net = attach_mock_network(*core);

    // A snapshot from another device, arriving under a hash of its own.  A "G" carries the whole
    // group rather than its author's part of it, so once we have taken its contents in, the message
    // we push next says everything it said -- which is what makes it redundant, whoever wrote it.
    auto theirs = core->devices.build_device_group_message().message;
    TestHelper::receive_device_group_message(core->devices, theirs, "theirs1");

    TestHelper::poll(*core);
    finish_poll(*core, *mock_net);

    auto sent = pushes(*mock_net);
    REQUIRE(sent.size() == 1);
    auto reqs = push_requests(*sent[0]);

    REQUIRE(reqs.size() == 2);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[1]["method"] == "delete");
    CHECK(reqs[1]["params"]["messages"] == nlohmann::json::array({"theirs1"}));
}

TEST_CASE(
        "Devices: a key minted while a push is in flight is still owed", "[core][poll][devices]") {
    TempCore core;
    auto* mock_net = attach_mock_network(*core);

    TestHelper::poll(*core);
    finish_poll(*core, *mock_net);

    auto sent = pushes(*mock_net);
    REQUIRE(sent.size() == 1);
    auto confirm = sent[0]->callback;

    // Between the message being built and the swarm answering.  This seed is in no message that has
    // been sent, so confirming the one in flight must not mark it distributed -- no other device
    // would ever receive it, and messages encrypted to it would be undecryptable for them.
    core->devices.rotate_account_keys();

    confirm(true,
            false,
            200,
            {},
            nlohmann::json{{"results", {{{"code", 200}, {"body", {{"hash", "group1"}}}}}}}.dump());
    TestHelper::drain(*core);

    TestHelper::poll(*core);
    finish_poll(*core, *mock_net);

    CHECK(pushes(*mock_net).size() == 2);
}
