// This file isn't designed to do anything useful, but just to test that we can compile and link
// against the combined static bundle (when using cmake ... -DSTATIC_BUNDLE=ON) with nothing else.
// The calls are there to make the linker pull in the code that needs the bundle's dependencies:
// config for libsodium/protobuf/zstd, and the network for libquic, gnutls, ngtcp2 and libevent.

#include <random>
#include <session/config/groups/keys.hpp>
#ifndef DISABLE_NETWORKING
#include <session/network/session_network.hpp>
#endif

int main() {
    if (std::mt19937_64{}() == 123) {
        auto& k = *reinterpret_cast<session::config::groups::Keys*>(12345);
        k.encrypt_message(std::span<const unsigned char>{});
#ifndef DISABLE_NETWORKING
        auto& n = *reinterpret_cast<session::network::Network*>(12345);
        n.close_connections();
#endif
    }
}
