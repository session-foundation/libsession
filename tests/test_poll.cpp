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

// A batch response shaped to the request, carrying a single message in the subrequest that asked
// for `ns` and nothing in the rest.
static nlohmann::json make_response(
        std::span<const std::byte> request_body,
        int16_t ns,
        std::vector<std::byte> msg_data,
        std::string hash) {
    return retrieve_response(request_body, ns, {{std::move(hash), std::move(msg_data)}});
}

TEST_CASE("Core automatic polling", "[core][poll]") {
    bool received = false;
    core::callbacks cbs;
    cbs.device_link_request = [&](int,
                                  const core::device::Info&,
                                  std::span<const std::string_view>) { received = true; };

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
    auto outer_msg = linker->devices.build_link_request(await).message;

    sent.callback(
            true, false, 200, {}, make_response(*sent.request.body, 21, outer_msg, "hash1").dump());
    TestHelper::drain(*core);

    // Verify last_hash was stored under this specific node's pubkey.
    CHECK(TestHelper::namespace_last_hash(*core, 21, mock_net->current_node.remote_pubkey) ==
          "hash1");
    CHECK(received);

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
    core::callbacks cbs;
    cbs.device_link_request =
            [&](int, const core::device::Info&, std::span<const std::string_view>) {
                called = true;
                hash_during_callback = TestHelper::namespace_last_hash(
                        *core_ptr, 21, mock_net->current_node.remote_pubkey);
            };

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
    auto outer_msg = linker->devices.build_link_request(await).message;

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
    int calls = 0;
    core::callbacks cbs;
    cbs.device_link_request =
            [&](int, const core::device::Info&, std::span<const std::string_view>) { calls++; };

    TempCore core{cbs};
    auto* mock_net = attach_mock_network(*core);
    mock_net->current_node.remote_pubkey[0] = std::byte{0x01};

    cleared_b32 seed_bytes;
    {
        auto seed_acc = core->globals.account_seed();
        std::ranges::copy(std::as_bytes(seed_acc.seed()), seed_bytes.begin());
    }
    TempCore linker{core::predefined_seed{std::span<const std::byte, 32>{seed_bytes}}};
    auto outer_msg = linker->devices.build_link_request(await).message;

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
    CHECK(calls == 0);

    REQUIRE(mock_net->sent_requests.size() == 2);
    auto second = *mock_net->sent_requests[1].request.body;
    CHECK(namespaces_in(second) == std::vector<int16_t>{21});
    CHECK(params_for(second, 21)["last_hash"] == "hash1");

    // Nothing left behind it: an empty answer is still an answer, and is what makes the batch
    // final.
    auto reply2 = mock_net->sent_requests[1].callback;
    reply2(true, false, 200, {}, make_empty_response(second).dump());
    TestHelper::drain(*core);

    CHECK(calls == 1);
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
    CHECK(mock_net->sent_requests.size() == 1);
}
