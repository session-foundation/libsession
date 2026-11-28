#pragma once

#include "common.hpp"

/// Building what "another device on this account" pushed, and feeding it back in as a retrieve
/// would.
/// Shared by every test whose subject is reconciliation between the configs and the database.
namespace client_test {

/// What another device on this account pushed to its UserProfile.  Another device is exactly this:
/// a second config object holding the same account key.
inline std::vector<std::vector<std::byte>> profile_from_another_device(
        Client& c, const std::function<void(config::UserProfile&)>& change) {
    // The other device has seen what we published, rather than being invented alongside us: it is
    // built from our own dump once ours has gone out.  Starting it from nothing would make a rival
    // at the same seqno, which is a different scenario entirely -- and one that resolves by merging
    // the two sets of changes rather than by taking theirs.
    // On Core's loop, like every other reach into the configs: they are the loop's, and a test is
    // on its own thread like any other application.
    return TestHelper::on_loop(c.core, [&] {
        auto& ours = c.core.configs.user_profile();
        auto [seqno, messages, obsolete] = ours.push();
        ours.confirm_pushed(seqno, {"ourprofile"});

        auto seed = c.core.globals.account_seed();
        config::UserProfile theirs{seed.ed25519_secret(), ours.make_dump()};
        change(theirs);
        auto [their_seqno, their_messages, their_obsolete] = theirs.push();
        return their_messages;
    });
}

/// Feeds them in as a retrieve would.  A SwarmMessage points at its data rather than owning it, so
/// `messages` has to outlive this call.
inline void merge_profile(Client& c, const std::vector<std::vector<std::byte>>& messages) {
    std::vector<core::SwarmMessage> incoming;
    for (size_t i = 0; i < messages.size(); i++) {
        core::SwarmMessage m;
        m.hash = fmt::format("profilehash{}", i);
        m.data = messages[i];
        incoming.push_back(std::move(m));
    }
    // Merging is config work, so it belongs on Core's loop just as a real retrieve's would.
    TestHelper::on_loop(c.core, [&] {
        c.core.receive_messages(incoming, config::Namespace::UserProfile, true);
    });
}

inline ConversationId self_convo(Client& c) {
    return ConversationId::dm(c.core.globals.session_id());
}

inline bool listed(Client& c, const ConversationId& id) {
    auto all = c.conversations(await);
    return std::ranges::any_of(all, [&](const auto& x) { return x.id() == id; });
}

/// What another device pushed to its Contacts config, having set up one contact however the caller
/// says.
inline std::vector<std::vector<std::byte>> contacts_from_another_device(
        Client& c,
        std::string_view session_id,
        const std::function<void(config::contact_info&)>& change) {
    auto seed = c.core.globals.account_seed();
    config::Contacts theirs{seed.ed25519_secret(), std::nullopt};
    auto entry = theirs.get_or_construct(std::string{session_id});
    change(entry);
    theirs.set(entry);
    auto [seqno, messages, obsolete] = theirs.push();
    return messages;
}

/// A further push from a device that has seen ours: built from our own dump once ours has gone out,
/// so it descends from our history rather than being a rival at the same seqno.  A rival merges to
/// the union of the two, which is right but is never what a test about *removal* wants.
inline std::vector<std::vector<std::byte>> contacts_update_from_another_device(
        Client& c, const std::function<void(config::Contacts&)>& change) {
    return TestHelper::on_loop(c.core, [&] {
        auto& ours = c.core.configs.contacts();
        auto [seqno, messages, obsolete] = ours.push();
        ours.confirm_pushed(seqno, {"ourcontacts"});

        auto seed = c.core.globals.account_seed();
        config::Contacts theirs{seed.ed25519_secret(), ours.make_dump()};
        change(theirs);
        auto [their_seqno, their_messages, their_obsolete] = theirs.push();
        return their_messages;
    });
}

inline ConversationId dm_from_hex(std::string_view hex) {
    auto raw = oxenc::from_hex(hex);
    b33 sid;
    std::memcpy(sid.data(), raw.data(), sid.size());
    return ConversationId::dm(sid);
}

/// Puts a message into a DM at a chosen moment, which is what a test about deleting by timestamp
/// needs and what send_message cannot give it.
inline void insert_message(
        Client& c, const ConversationId& id, int64_t timestamp, std::string body) {
    auto conn = c.core.database().conn();
    conn.prepared_exec(
            R"(
        INSERT INTO messages (conversation, sender, outgoing, timestamp, body)
        VALUES ((SELECT c.id FROM conversations c JOIN accounts a ON a.id = c.dm
                  WHERE a.session_id = ?1),
                (SELECT id FROM accounts WHERE session_id = ?1), 0, ?2, ?3)
    )",
            id.session_id(),
            timestamp,
            body);
}

/// A ConvoInfoVolatile update from a device that has seen ours, built the same way and for the same
/// reason as `contacts_update_from_another_device`.
inline std::vector<std::vector<std::byte>> volatile_from_another_device(
        Client& c, const std::function<void(config::ConvoInfoVolatile&)>& change) {
    return TestHelper::on_loop(c.core, [&] {
        auto& ours = c.core.configs.convo_info_volatile();
        auto [seqno, messages, obsolete] = ours.push();
        ours.confirm_pushed(seqno, {"ourvolatile"});

        auto seed = c.core.globals.account_seed();
        config::ConvoInfoVolatile theirs{seed.ed25519_secret(), ours.make_dump()};
        change(theirs);
        auto [their_seqno, their_messages, their_obsolete] = theirs.push();
        return their_messages;
    });
}

inline void merge_volatile(Client& c, const std::vector<std::vector<std::byte>>& messages) {
    std::vector<core::SwarmMessage> incoming;
    for (size_t i = 0; i < messages.size(); i++) {
        core::SwarmMessage m;
        m.hash = fmt::format("volatilehash{}", i);
        m.data = messages[i];
        incoming.push_back(std::move(m));
    }
    TestHelper::on_loop(c.core, [&] {
        c.core.receive_messages(incoming, config::Namespace::ConvoInfoVolatile, true);
    });
}

inline void merge_contacts(Client& c, const std::vector<std::vector<std::byte>>& messages) {
    std::vector<core::SwarmMessage> incoming;
    for (size_t i = 0; i < messages.size(); i++) {
        core::SwarmMessage m;
        m.hash = fmt::format("contacthash{}", i);
        m.data = messages[i];
        incoming.push_back(std::move(m));
    }
    TestHelper::on_loop(
            c.core, [&] { c.core.receive_messages(incoming, config::Namespace::Contacts, true); });
}

}  // namespace client_test
