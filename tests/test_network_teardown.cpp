#include <catch2/catch_test_macros.hpp>
#include <future>
#include <session/network/session_network.hpp>
#include <thread>

#include "test_helper.hpp"

using namespace session;
using namespace session::network;
using namespace std::literals;

TEST_CASE(
        "Network: an owner reference dropped mid-callback does not tear the Network down from its "
        "own loop",
        "[network]") {
    auto net = std::make_shared<Network>(network::config::Config{});

    // get_swarm answers from the SnodePool's loop, so the callback below runs on the loop thread
    // rather than on this one.  (This used to be reached through the swarm retry, which answered
    // from the loop for the same reason; that has moved to Core, so the vehicle is different but
    // the interleaving under test is the same.)
    auto swarm_pubkey = x25519_pubkey::from_hex(std::string(64, 'a'));
    TestHelper::seed_swarm(
            TestHelper::snode_pool(*net),
            swarm_pubkey,
            {service_node{
                    ed25519_pubkey::from_hex(std::string(64, 'b')),
                    oxen::quic::ipv4{127, 0, 0, 1},
                    1001,
                    2001,
                    {2, 8, 0},
                    0,
                    0}});

    auto reached_callback = std::promise<void>{};
    auto in_callback = reached_callback.get_future();
    std::atomic<bool> answered = false;

    net->get_swarm(swarm_pubkey, false, [&reached_callback, &answered](auto, auto swarm) {
        answered = !swarm.empty();
        reached_callback.set_value();

        // Stay on the loop thread while the reference below goes, which is the interleaving that
        // used to abort: a callback holding a shared_ptr<Network> of its own meant dropping the
        // owner's left the loop thread as the last owner, and ~Network joins that thread.
        std::this_thread::sleep_for(50ms);
    });

    REQUIRE(in_callback.wait_for(5s) == std::future_status::ready);

    auto observer = std::weak_ptr<Network>{net};
    net.reset();

    // Waits for the Network to actually be gone rather than merely unreferenced from here: the
    // teardown is what fails, so it has to happen while this test is still running.  Nothing else
    // holds a reference, so this returns as soon as the callback has finished.
    for (int i = 0; i < 500 && !observer.expired(); i++)
        std::this_thread::sleep_for(10ms);

    // Surviving to here is the assertion: the failure was an abort out of a destructor rather than
    // a wrong answer.
    CHECK(observer.expired());
    CHECK(answered);
}

TEST_CASE("Network: a disk loop it is given is the one it uses", "[network]") {
    // Shared, so that one thread does all of an account's work on disk: Core hands its own to the
    // Network it makes.
    auto shared = std::make_shared<oxen::quic::Loop>();
    {
        Network net{opt::disk_loop{shared}};
        CHECK(&TestHelper::disk_loop(net) == shared.get());
    }

    // And outlives the Network it was lent to, which only lets go of it.
    CHECK(shared.use_count() == 1);
    CHECK(shared->call_get([] { return 42; }) == 42);

    // Without one, a Network starts its own as it always has.
    Network own{network::config::Config{}};
    CHECK(&TestHelper::disk_loop(own) != shared.get());
}
