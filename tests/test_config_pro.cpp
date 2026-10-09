#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <session/config/pro.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include <session/config/pro.hpp>
using namespace oxenc::literals;

TEST_CASE("Pro", "[config][pro]") {
    // Setup keys
    std::array<uint8_t, crypto_sign_ed25519_PUBLICKEYBYTES> rotating_pk, signing_pk;
    session::cleared_uc64 rotating_sk, signing_sk;
    {
        crypto_sign_ed25519_keypair(rotating_pk.data(), rotating_sk.data());
        crypto_sign_ed25519_keypair(signing_pk.data(), signing_sk.data());
    }

    // Setup the Pro data structure
    session::config::ProConfig pro_cpp = {};
    pro_pro_config pro = {};
    {
        // CPP
        pro_cpp.rotating_privkey = rotating_sk;
        pro_cpp.proof.rotating_pubkey = rotating_pk;
        pro_cpp.proof.expiry_at = std::chrono::sys_seconds(1s);
        constexpr auto revocation_tag =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_u;
        static_assert(pro_cpp.proof.revocation_tag.max_size() == revocation_tag.size());
        std::memcpy(
                pro_cpp.proof.revocation_tag.data(), revocation_tag.data(), revocation_tag.size());

        // C
        std::memcpy(pro.rotating_privkey.data, rotating_sk.data(), rotating_sk.size());
        std::memcpy(pro.proof.rotating_pubkey.data, rotating_pk.data(), rotating_pk.size());
        pro.proof.expiry_ts = pro_cpp.proof.expiry_at.time_since_epoch().count();
        std::memcpy(pro.proof.revocation_tag.data, revocation_tag.data(), revocation_tag.size());
    }

    // Sign the proof with the faux pro backend key (Ed25519 over the message directly). The C and
    // C++ proof representations above mirror each other, so a single message signs both.
    {
        static_assert(crypto_sign_ed25519_BYTES == pro_cpp.proof.sig.max_size());
        auto msg_to_sign = pro_cpp.proof.signed_message();

        // Write the signature into the C++ proof
        int sig_result = crypto_sign_ed25519_detached(
                pro_cpp.proof.sig.data(),
                nullptr,
                msg_to_sign.data(),
                msg_to_sign.size(),
                signing_sk.data());
        CHECK(sig_result == 0);

        // ... and into the C proof
        sig_result = crypto_sign_ed25519_detached(
                pro.proof.sig.data,
                nullptr,
                msg_to_sign.data(),
                msg_to_sign.size(),
                signing_sk.data());
        CHECK(sig_result == 0);
    }

    // Verify expiry
    {
        CHECK(pro_cpp.proof.is_active(pro_cpp.proof.expiry_at));
        CHECK_FALSE(pro_cpp.proof.is_active(pro_cpp.proof.expiry_at + 1s));

        CHECK(session_protocol_pro_proof_is_active(&pro.proof, pro.proof.expiry_ts));
        CHECK_FALSE(session_protocol_pro_proof_is_active(&pro.proof, pro.proof.expiry_ts + 1));
    }

    // Verify it can verify messages signed with the rotating public key
    {
        std::string_view body = "hello world";
        std::array<uint8_t, crypto_sign_ed25519_BYTES> sig = {};
        int sign_result = crypto_sign_ed25519_detached(
                sig.data(),
                nullptr,
                reinterpret_cast<const uint8_t*>(body.data()),
                body.size(),
                rotating_sk.data());
        CHECK(sign_result == 0);
        CHECK(pro_cpp.proof.verify_message(sig, session::to_span(body)));
        CHECK(session_protocol_pro_proof_verify_message(
                &pro.proof,
                sig.data(),
                sig.size(),
                reinterpret_cast<const uint8_t*>(body.data()),
                body.size()));
    }

    // Round-trip the proof through its bt-encoded config value.
    {
        std::string encoded = pro_cpp.serialize();

        session::config::ProConfig loaded_pro = {};
        CHECK(loaded_pro.load(encoded));
        CHECK(loaded_pro.rotating_privkey == pro_cpp.rotating_privkey);
        CHECK(loaded_pro.proof.revocation_tag == pro_cpp.proof.revocation_tag);
        CHECK(loaded_pro.proof.rotating_pubkey ==
              pro_cpp.proof.rotating_pubkey);  // derived from seed
        CHECK(loaded_pro.proof.expiry_at == pro_cpp.proof.expiry_at);
        CHECK(loaded_pro.proof.sig == pro_cpp.proof.sig);
        CHECK(loaded_pro.proof.verify_signature(signing_pk));
    }

    // A tampered signature still loads (load doesn't verify) but fails verify_signature.
    {
        pro_cpp.proof.sig.data()[0] = ~pro_cpp.proof.sig.data()[0];  // break the sig
        std::string encoded = pro_cpp.serialize();

        session::config::ProConfig loaded_pro = {};
        CHECK(loaded_pro.load(encoded));
        CHECK_FALSE(loaded_pro.proof.verify_signature(signing_pk));
    }
}
