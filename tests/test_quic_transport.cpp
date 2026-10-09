#include <catch2/catch_test_macros.hpp>
#include <future>
#include <session/network/session_network_types.hpp>
#include <session/network/transport/quic_transport.hpp>

using namespace session::network;
using namespace std::literals;

namespace {
std::shared_ptr<QuicTransport> make_transport(oxen::quic::Loop& loop) {
    return std::make_shared<QuicTransport>(
            config::QuicTransport{.handshake_timeout = 1s, .keep_alive = 10s}, loop);
}

service_node test_node() {
    auto pubkey = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"sv;
    return service_node{
            ed25519_pubkey::from_hex(pubkey),
            oxen::quic::ipv4{"127.0.0.1"},
            20001,
            30001,
            {2, 11, 0},
            0};
}
}  // namespace

TEST_CASE("Network", "[network][quic_transport][suspend]") {
    auto loop = std::make_shared<oxen::quic::Loop>();
    auto transport = make_transport(*loop);
    transport->suspend();

    std::promise<int16_t> status;
    transport->send_request(
            Request{"AAAA", test_node(), "info", std::nullopt, RequestCategory::standard, 1s},
            [&status, answered = false](bool, bool, int16_t status_code, auto, auto) mutable {
                if (!std::exchange(answered, true))
                    status.set_value(status_code);
            });

    // Refused outright rather than attempted: a suspended transport sends nothing
    auto answer = status.get_future();
    REQUIRE(answer.wait_for(5s) == std::future_status::ready);
    CHECK(answer.get() == ERROR_NETWORK_SUSPENDED);
}

TEST_CASE("Network", "[network][quic_transport][close_connections]") {
    auto loop = std::make_shared<oxen::quic::Loop>();
    auto transport = make_transport(*loop);

    // Verified and closed within one loop job, so nothing from the network can settle the
    // verification before the close does
    int answers = 0;
    bool success = true;
    std::optional<uint64_t> error_code;
    loop->call_get([&] {
        transport->verify_connectivity(
                test_node(),
                3s,
                "AAAA",
                RequestCategory::standard,
                [&](bool s, std::optional<uint64_t> e) {
                    ++answers;
                    success = s;
                    error_code = e;
                });
        transport->close_connections();
    });

    // Anything the close deferred has run by the time a later job does
    loop->call_get([] {});

    // One answer, from the close, and with no error code: a close we asked for is no evidence
    // against the node, which is what an error code would say - the router strikes a node whose
    // verification fails with one
    CHECK(answers == 1);
    CHECK_FALSE(success);
    CHECK_FALSE(error_code);
}
