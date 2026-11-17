#include <fcntl.h>
#include <session/network/session_network.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <future>
#include <session/network/session_network_types.hpp>
#include <session/network/transport/quic_transport.hpp>
#include <vector>

using namespace session::network;
using namespace std::literals;

namespace {
// Takes every file descriptor the process may open, under a lowered limit, so that the next
// socket() fails with EMFILE - a real failure of the endpoint's own socket setup, rather than an
// injected one.  The descriptors and the limit are given back on destruction.
class exhausted_file_descriptors {
    rlimit _original{};
    std::vector<int> _fds;

  public:
    exhausted_file_descriptors() {
        getrlimit(RLIMIT_NOFILE, &_original);
        auto lowered = _original;
        lowered.rlim_cur = std::min<rlim_t>(_original.rlim_cur, 1024);
        setrlimit(RLIMIT_NOFILE, &lowered);

        for (int fd; (fd = ::open("/dev/null", O_RDONLY)) >= 0;)
            _fds.push_back(fd);
    }

    ~exhausted_file_descriptors() {
        for (int fd : _fds)
            ::close(fd);
        setrlimit(RLIMIT_NOFILE, &_original);
    }

    // Whether a socket can't be opened, which is what the tests below rely on
    static bool socket_fails() {
        int sock = ::socket(AF_INET6, SOCK_DGRAM, 0);
        if (sock < 0)
            return true;
        ::close(sock);
        return false;
    }
};

std::shared_ptr<QuicTransport> make_transport(std::shared_ptr<oxen::quic::Loop> loop) {
    return std::make_shared<QuicTransport>(
            config::QuicTransport{
                    .handshake_timeout = 1s,
                    .keep_alive = 10s,
                    .max_udp_payload = std::nullopt,
                    .congestion_control = std::nullopt},
            std::move(loop));
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
    auto transport = make_transport(loop);
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
    auto transport = make_transport(loop);

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

TEST_CASE("Network", "[network][quic_transport][resume]") {
    auto loop = std::make_shared<oxen::quic::Loop>();
    auto transport = make_transport(loop);
    transport->suspend();

    {
        exhausted_file_descriptors no_fds;
        REQUIRE(exhausted_file_descriptors::socket_fails());

        // Throwing here would reach the C API's caller, which can't catch it
        CHECK_NOTHROW(transport->resume(true));
    }

    // Once sockets can be opened again a connection attempt rebuilds the endpoint, so it is made
    // and times out with an error code; without an endpoint it would fail at once with none
    std::promise<std::optional<uint64_t>> error_code;
    transport->verify_connectivity(
            test_node(),
            3s,
            "AAAA",
            RequestCategory::standard,
            [&error_code, answered = false](bool, std::optional<uint64_t> e) mutable {
                if (!std::exchange(answered, true))
                    error_code.set_value(e);
            });

    auto answer = error_code.get_future();
    REQUIRE(answer.wait_for(10s) == std::future_status::ready);
    CHECK(answer.get().has_value());
}

TEST_CASE("Network", "[network][c_api][resume]") {
    // Devnet with a local seed node keeps the network's own startup requests off the internet
    network_service_node seed{};
    std::strcpy(
            seed.ed25519_pubkey_hex,
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    seed.ip[0] = 127;
    seed.ip[3] = 1;
    seed.https_port = 20001;
    seed.omq_port = 30001;
    seed.version[0] = 2;
    seed.version[1] = 11;

    auto config = session_network_config_default();
    config.netid = SESSION_NETWORK_DEVNET;
    config.router = SESSION_NETWORK_ROUTER_DIRECT;
    config.devnet_seed_nodes = &seed;
    config.devnet_seed_nodes_size = 1;

    network_object* network = nullptr;
    char error[256] = {};
    REQUIRE(session_network_init(&network, &config, error));

    session_network_suspend(network);
    {
        exhausted_file_descriptors no_fds;
        REQUIRE(exhausted_file_descriptors::socket_fails());
        CHECK_NOTHROW(session_network_resume(network, false));
    }

    session_network_free(network);
}
