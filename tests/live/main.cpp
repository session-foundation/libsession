#include <catch2/catch_session.hpp>
#include <oxen/log.hpp>
#include <session/network/network_opt.hpp>

#include "../log_setup.hpp"

// Router selection: consumed by make_testnet_core() in live_utils.hpp.
session::network::opt::router live_router_mode = session::network::opt::router::session_router();

int main(int argc, char* argv[]) {
    Catch::Session session;

    using namespace Catch::Clara;
    using session::network::opt::router;
    LogSetup log;
    log.level = "warning";

    bool use_srouter = false, use_onionreq = false, use_direct = false;

    auto cli = session.cli() | log.opts() |
               Opt(use_srouter)["--srouter"]("route requests via session-router") |
               Opt(use_onionreq)["--onionreq"]("route requests via onion requests") |
               Opt(use_direct)["--direct"]("route requests directly (no onion routing)");

    session.cli(cli);

    if (int rc = session.applyCommandLine(argc, argv); rc != 0)
        return rc;

    if (int n = use_srouter + use_onionreq + use_direct; n > 1) {
        oxen::log::critical(
                oxen::log::Cat("live-test"),
                "--srouter, --onionreq, and --direct are mutually exclusive");
        return 1;
    }

    if (use_direct)
        live_router_mode = router::direct();
    else if (use_onionreq)
        live_router_mode = router::onion_requests();
    else if (use_srouter)
        live_router_mode = router::session_router();

    log.apply();

    return session.run();
}
